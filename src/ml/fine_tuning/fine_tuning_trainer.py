"""
Solidity Security LLM Fine-Tuning Trainer

Provides training infrastructure for fine-tuning LLMs on Solidity security analysis.
Supports multiple backends: Hugging Face Transformers, Axolotl, and Ollama.

Author: Fernando Boiero
License: GPL-3.0
"""

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class TrainingConfig:
    """Configuration for fine-tuning training."""
    # Model settings
    base_model: str = "deepseek-ai/deepseek-coder-6.7b-instruct"
    output_dir: str = "models/solidity-security-llm"

    # Training hyperparameters
    num_epochs: int = 3
    batch_size: int = 4
    gradient_accumulation_steps: int = 4
    learning_rate: float = 2e-5
    warmup_ratio: float = 0.1
    weight_decay: float = 0.01
    max_seq_length: int = 2048

    # LoRA settings (for efficient fine-tuning)
    use_lora: bool = True
    lora_r: int = 16
    lora_alpha: int = 32
    lora_dropout: float = 0.05
    lora_target_modules: List[str] = field(default_factory=lambda: [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj"
    ])

    # Quantization
    use_4bit: bool = True
    bnb_4bit_compute_dtype: str = "float16"
    bnb_4bit_quant_type: str = "nf4"

    # Training options
    gradient_checkpointing: bool = True
    flash_attention: bool = True
    bf16: bool = True
    fp16: bool = False

    # Evaluation
    eval_steps: int = 100
    save_steps: int = 100
    logging_steps: int = 10


class SoliditySecurityTrainer:
    """
    Trainer class for fine-tuning LLMs on Solidity security.

    Supports multiple training backends:
    - Hugging Face Transformers + PEFT
    - Axolotl (for advanced distributed training)
    - Ollama Modelfile (for local deployment)
    """

    def __init__(self, config: Optional[TrainingConfig] = None):
        """Initialize trainer with configuration."""
        self.config = config or TrainingConfig()
        self.model = None
        self.tokenizer = None

    def check_dependencies(self) -> Dict[str, bool]:
        """Check if required dependencies are installed."""
        dependencies = {
            "torch": False,
            "transformers": False,
            "peft": False,
            "bitsandbytes": False,
            "datasets": False,
            "trl": False,
            "accelerate": False
        }

        for dep in dependencies:
            try:
                __import__(dep)
                dependencies[dep] = True
            except ImportError:
                pass

        return dependencies

    def install_dependencies(self) -> None:
        """Install required dependencies."""
        packages = [
            "torch",
            "transformers>=4.36.0",
            "peft>=0.7.0",
            "bitsandbytes>=0.41.0",
            "datasets>=2.15.0",
            "trl>=0.7.0",
            "accelerate>=0.25.0",
            "scipy",
            "sentencepiece"
        ]

        logger.info("Installing dependencies...")
        subprocess.run([
            sys.executable, "-m", "pip", "install", *packages
        ], check=True)

    def prepare_model(self) -> None:
        """Load and prepare the base model for fine-tuning."""
        try:
            import torch
            from transformers import (
                AutoModelForCausalLM,
                AutoTokenizer,
                BitsAndBytesConfig
            )
            from peft import LoraConfig, prepare_model_for_kbit_training, get_peft_model
        except ImportError as e:
            raise ImportError(f"Missing dependency: {e}. Run install_dependencies() first.")

        logger.info(f"Loading base model: {self.config.base_model}")

        # Quantization config
        if self.config.use_4bit:
            bnb_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_compute_dtype=getattr(torch, self.config.bnb_4bit_compute_dtype),
                bnb_4bit_quant_type=self.config.bnb_4bit_quant_type,
                bnb_4bit_use_double_quant=True
            )
        else:
            bnb_config = None

        # Load tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(
            self.config.base_model,
            trust_remote_code=True
        )
        self.tokenizer.pad_token = self.tokenizer.eos_token
        self.tokenizer.padding_side = "right"

        # Load model
        self.model = AutoModelForCausalLM.from_pretrained(
            self.config.base_model,
            quantization_config=bnb_config,
            device_map="auto",
            trust_remote_code=True,
            torch_dtype=torch.float16 if self.config.fp16 else torch.bfloat16
        )

        # Enable gradient checkpointing
        if self.config.gradient_checkpointing:
            self.model.gradient_checkpointing_enable()

        # Prepare for k-bit training
        if self.config.use_4bit:
            self.model = prepare_model_for_kbit_training(self.model)

        # Apply LoRA
        if self.config.use_lora:
            lora_config = LoraConfig(
                r=self.config.lora_r,
                lora_alpha=self.config.lora_alpha,
                lora_dropout=self.config.lora_dropout,
                target_modules=self.config.lora_target_modules,
                bias="none",
                task_type="CAUSAL_LM"
            )
            self.model = get_peft_model(self.model, lora_config)

        logger.info("Model prepared successfully")
        self.model.print_trainable_parameters()

    def load_dataset(self, dataset_path: str) -> Any:
        """Load and preprocess the training dataset."""
        try:
            from datasets import load_dataset
        except ImportError:
            raise ImportError("datasets package not installed")

        logger.info(f"Loading dataset from: {dataset_path}")

        # Determine format based on file extension
        if dataset_path.endswith(".jsonl"):
            dataset = load_dataset("json", data_files=dataset_path, split="train")
        elif dataset_path.endswith(".json"):
            dataset = load_dataset("json", data_files=dataset_path, split="train")
        else:
            dataset = load_dataset(dataset_path, split="train")

        return dataset

    def format_instruction(self, example: Dict[str, Any]) -> str:
        """Format a single example for training."""
        # Handle ChatML format
        if "messages" in example:
            formatted = ""
            for msg in example["messages"]:
                role = msg["role"]
                content = msg["content"]
                if role == "system":
                    formatted += f"<|system|>\n{content}\n"
                elif role == "user":
                    formatted += f"<|user|>\n{content}\n"
                elif role == "assistant":
                    formatted += f"<|assistant|>\n{content}\n"
            return formatted

        # Handle Alpaca format
        if "instruction" in example:
            text = f"### Instruction:\n{example['instruction']}\n\n"
            if example.get("input"):
                text += f"### Input:\n{example['input']}\n\n"
            text += f"### Response:\n{example['output']}"
            return text

        return str(example)

    def train(self, dataset_path: str) -> str:
        """Run the fine-tuning training process."""
        try:
            from transformers import TrainingArguments
            from trl import SFTTrainer
        except ImportError as e:
            raise ImportError(f"Missing dependency: {e}")

        if self.model is None:
            self.prepare_model()

        # Load dataset
        dataset = self.load_dataset(dataset_path)

        # Training arguments
        training_args = TrainingArguments(
            output_dir=self.config.output_dir,
            num_train_epochs=self.config.num_epochs,
            per_device_train_batch_size=self.config.batch_size,
            gradient_accumulation_steps=self.config.gradient_accumulation_steps,
            learning_rate=self.config.learning_rate,
            warmup_ratio=self.config.warmup_ratio,
            weight_decay=self.config.weight_decay,
            logging_steps=self.config.logging_steps,
            save_steps=self.config.save_steps,
            eval_steps=self.config.eval_steps,
            bf16=self.config.bf16,
            fp16=self.config.fp16,
            gradient_checkpointing=self.config.gradient_checkpointing,
            optim="paged_adamw_32bit",
            lr_scheduler_type="cosine",
            report_to="tensorboard",
            save_total_limit=3,
            push_to_hub=False
        )

        # Initialize trainer
        trainer = SFTTrainer(
            model=self.model,
            tokenizer=self.tokenizer,
            train_dataset=dataset,
            args=training_args,
            max_seq_length=self.config.max_seq_length,
            formatting_func=self.format_instruction,
            packing=True
        )

        logger.info("Starting training...")
        trainer.train()

        # Save the model
        trainer.save_model()
        self.tokenizer.save_pretrained(self.config.output_dir)

        logger.info(f"Model saved to: {self.config.output_dir}")
        return self.config.output_dir

    def merge_lora_weights(self, output_path: str) -> str:
        """Merge LoRA weights with base model for deployment."""
        try:
            from peft import PeftModel
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as e:
            raise ImportError(f"Missing dependency: {e}")

        logger.info("Merging LoRA weights with base model...")

        # Load base model
        base_model = AutoModelForCausalLM.from_pretrained(
            self.config.base_model,
            device_map="auto",
            trust_remote_code=True
        )

        # Load LoRA weights
        model = PeftModel.from_pretrained(base_model, self.config.output_dir)

        # Merge weights
        merged_model = model.merge_and_unload()

        # Save merged model
        merged_model.save_pretrained(output_path)

        # Copy tokenizer
        tokenizer = AutoTokenizer.from_pretrained(self.config.output_dir)
        tokenizer.save_pretrained(output_path)

        logger.info(f"Merged model saved to: {output_path}")
        return output_path

    def generate_ollama_modelfile(self, model_path: str) -> str:
        """Generate Ollama Modelfile for local deployment."""
        modelfile_content = f'''# MIESC Solidity Security LLM
# Fine-tuned for smart contract vulnerability detection

FROM {model_path}

# System prompt for security analysis
SYSTEM """You are an expert Solidity security auditor specializing in smart contract vulnerability detection and remediation. You analyze code for security issues including:

- Reentrancy attacks
- Integer overflow/underflow
- Access control vulnerabilities
- Unchecked return values
- Oracle manipulation
- Flash loan attacks
- Signature replay
- DoS vulnerabilities
- Front-running risks

When analyzing code, provide:
1. Identified vulnerabilities with severity ratings
2. Clear explanation of the attack vector
3. Recommended fixes with code examples
4. References to CWE and SWC classifications"""

# Model parameters optimized for code analysis
PARAMETER temperature 0.2
PARAMETER top_p 0.9
PARAMETER top_k 40
PARAMETER repeat_penalty 1.1
PARAMETER num_ctx 4096

# Template for code analysis
TEMPLATE """{{{{if .System}}}}{{{{.System}}}}{{{{end}}}}

### User:
{{{{.Prompt}}}}

### Assistant:
"""
'''

        modelfile_path = Path(model_path) / "Modelfile"
        with open(modelfile_path, "w") as f:
            f.write(modelfile_content)

        logger.info(f"Ollama Modelfile generated: {modelfile_path}")
        return str(modelfile_path)

    def create_ollama_model(self, model_name: str, modelfile_path: str) -> bool:
        """Create Ollama model from Modelfile."""
        try:
            result = subprocess.run(
                ["ollama", "create", model_name, "-f", modelfile_path],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                logger.info(f"Ollama model '{model_name}' created successfully")
                return True
            else:
                logger.error(f"Failed to create Ollama model: {result.stderr}")
                return False
        except FileNotFoundError:
            logger.error("Ollama CLI not found. Please install Ollama first.")
            return False

    def generate_axolotl_config(self, dataset_path: str) -> str:
        """Generate Axolotl configuration for distributed training."""
        config = {
            "base_model": self.config.base_model,
            "model_type": "AutoModelForCausalLM",
            "tokenizer_type": "AutoTokenizer",
            "is_llama_derived_model": False,
            "trust_remote_code": True,

            "load_in_8bit": False,
            "load_in_4bit": self.config.use_4bit,
            "strict": False,

            "datasets": [
                {
                    "path": dataset_path,
                    "type": "alpaca"
                }
            ],
            "dataset_prepared_path": "last_run_prepared",

            "val_set_size": 0.05,
            "output_dir": self.config.output_dir,

            "sequence_len": self.config.max_seq_length,
            "sample_packing": True,
            "pad_to_sequence_len": True,

            "adapter": "lora" if self.config.use_lora else None,
            "lora_r": self.config.lora_r,
            "lora_alpha": self.config.lora_alpha,
            "lora_dropout": self.config.lora_dropout,
            "lora_target_modules": self.config.lora_target_modules,
            "lora_target_linear": True,

            "gradient_accumulation_steps": self.config.gradient_accumulation_steps,
            "micro_batch_size": self.config.batch_size,
            "num_epochs": self.config.num_epochs,
            "optimizer": "paged_adamw_32bit",
            "lr_scheduler": "cosine",
            "learning_rate": self.config.learning_rate,
            "warmup_ratio": self.config.warmup_ratio,
            "weight_decay": self.config.weight_decay,

            "train_on_inputs": False,
            "group_by_length": False,
            "bf16": self.config.bf16,
            "fp16": self.config.fp16,
            "tf32": False,

            "gradient_checkpointing": self.config.gradient_checkpointing,
            "flash_attention": self.config.flash_attention,

            "logging_steps": self.config.logging_steps,
            "save_steps": self.config.save_steps,
            "eval_steps": self.config.eval_steps,
            "save_total_limit": 3,

            "special_tokens": {
                "pad_token": "<|pad|>"
            }
        }

        config_path = Path(self.config.output_dir) / "axolotl_config.yml"
        config_path.parent.mkdir(parents=True, exist_ok=True)

        import yaml
        with open(config_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False)

        logger.info(f"Axolotl config generated: {config_path}")
        return str(config_path)


def main():
    """Example usage of the fine-tuning trainer."""
    # Create configuration
    config = TrainingConfig(
        base_model="deepseek-ai/deepseek-coder-6.7b-instruct",
        output_dir="models/miesc-solidity-security",
        num_epochs=3,
        batch_size=4,
        use_lora=True,
        use_4bit=True
    )

    # Initialize trainer
    trainer = SoliditySecurityTrainer(config)

    # Check dependencies
    deps = trainer.check_dependencies()
    print("Dependencies status:")
    for dep, installed in deps.items():
        status = "OK" if installed else "MISSING"
        print(f"  {dep}: {status}")

    # Generate Axolotl config (for reference)
    axolotl_config = trainer.generate_axolotl_config("data/fine_tuning/solidity_security_alpaca.json")
    print(f"\nAxolotl config: {axolotl_config}")

    print("\nTo train the model, run:")
    print("  python -m src.ml.fine_tuning.fine_tuning_trainer --train data/fine_tuning/solidity_security_chatml.jsonl")


if __name__ == "__main__":
    main()
