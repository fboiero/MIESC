"""
MIESC Code Embeddings
Genera embeddings semánticos de código Solidity para análisis avanzado.
"""

import re
import hashlib
import math
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum


class TokenType(Enum):
    """Tipos de tokens en código Solidity."""
    KEYWORD = "keyword"
    TYPE = "type"
    MODIFIER = "modifier"
    FUNCTION = "function"
    VARIABLE = "variable"
    OPERATOR = "operator"
    LITERAL = "literal"
    COMMENT = "comment"
    OTHER = "other"


@dataclass
class CodeToken:
    """Token de código con metadata."""
    value: str
    token_type: TokenType
    position: int
    line: int


@dataclass
class CodeEmbedding:
    """Embedding de una sección de código."""
    source_hash: str
    vector: List[float]
    dimensions: int
    tokens: int
    code_type: str  # function, contract, modifier, etc.
    metadata: Dict[str, Any] = field(default_factory=dict)

    def similarity(self, other: 'CodeEmbedding') -> float:
        """Calcula similitud coseno con otro embedding."""
        if self.dimensions != other.dimensions:
            return 0.0

        dot_product = sum(a * b for a, b in zip(self.vector, other.vector))
        norm_a = math.sqrt(sum(a * a for a in self.vector))
        norm_b = math.sqrt(sum(b * b for b in other.vector))

        if norm_a == 0 or norm_b == 0:
            return 0.0

        return dot_product / (norm_a * norm_b)


class SolidityTokenizer:
    """Tokenizador especializado para Solidity."""

    KEYWORDS = {
        'pragma', 'solidity', 'contract', 'interface', 'library', 'abstract',
        'function', 'modifier', 'event', 'struct', 'enum', 'mapping',
        'public', 'private', 'internal', 'external', 'view', 'pure',
        'payable', 'virtual', 'override', 'immutable', 'constant',
        'if', 'else', 'for', 'while', 'do', 'return', 'require', 'revert',
        'assert', 'emit', 'new', 'delete', 'try', 'catch', 'using', 'is',
        'constructor', 'fallback', 'receive', 'storage', 'memory', 'calldata',
    }

    TYPES = {
        'uint', 'uint8', 'uint16', 'uint32', 'uint64', 'uint128', 'uint256',
        'int', 'int8', 'int16', 'int32', 'int64', 'int128', 'int256',
        'bytes', 'bytes1', 'bytes2', 'bytes4', 'bytes8', 'bytes16', 'bytes32',
        'string', 'address', 'bool', 'fixed', 'ufixed',
    }

    SECURITY_MODIFIERS = {
        'onlyOwner', 'nonReentrant', 'whenNotPaused', 'whenPaused',
        'onlyAdmin', 'onlyRole', 'initializer', 'reinitializer',
    }

    DANGEROUS_PATTERNS = {
        'selfdestruct', 'suicide', 'delegatecall', 'callcode',
        'tx.origin', 'block.timestamp', 'block.number',
        'assembly', 'extcodesize', 'create2',
    }

    OPERATORS = {
        '+', '-', '*', '/', '%', '**',
        '=', '==', '!=', '<', '>', '<=', '>=',
        '&&', '||', '!', '&', '|', '^', '~',
        '<<', '>>', '++', '--', '+=', '-=', '*=', '/=',
    }

    def tokenize(self, code: str) -> List[CodeToken]:
        """Tokeniza código Solidity."""
        tokens = []
        lines = code.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Remover comentarios de línea
            if '//' in line:
                comment_start = line.index('//')
                comment = line[comment_start:]
                line = line[:comment_start]
                tokens.append(CodeToken(
                    value=comment,
                    token_type=TokenType.COMMENT,
                    position=comment_start,
                    line=line_num,
                ))

            # Tokenizar resto de la línea
            words = re.findall(r'\b\w+\b|[+\-*/%=<>!&|^~]+|[.,;(){}[\]]', line)
            pos = 0

            for word in words:
                token_type = self._classify_token(word)
                tokens.append(CodeToken(
                    value=word,
                    token_type=token_type,
                    position=pos,
                    line=line_num,
                ))
                pos += len(word) + 1

        return tokens

    def _classify_token(self, token: str) -> TokenType:
        """Clasifica un token."""
        token_lower = token.lower()

        if token_lower in self.KEYWORDS:
            return TokenType.KEYWORD
        elif token_lower in self.TYPES or token_lower.startswith(('uint', 'int', 'bytes')):
            return TokenType.TYPE
        elif token in self.SECURITY_MODIFIERS:
            return TokenType.MODIFIER
        elif token in self.OPERATORS:
            return TokenType.OPERATOR
        elif re.match(r'^0x[0-9a-fA-F]+$', token) or token.isdigit():
            return TokenType.LITERAL
        elif token[0].isupper() and len(token) > 1:
            return TokenType.FUNCTION  # Likely a contract/struct name
        else:
            return TokenType.VARIABLE


class CodeEmbedder:
    """
    Generador de embeddings para código Solidity.

    Utiliza técnicas de:
    1. TF-IDF para features de vocabulario
    2. N-gramas para patrones de código
    3. Features estructurales (funciones, modifiers, etc.)
    4. Features de seguridad (patrones peligrosos)
    """

    def __init__(self, embedding_dim: int = 128):
        self.embedding_dim = embedding_dim
        self.tokenizer = SolidityTokenizer()
        self._vocabulary: Dict[str, int] = {}
        self._idf: Dict[str, float] = {}
        self._document_count = 0

    def _build_vocabulary(self, tokens: List[CodeToken]) -> Dict[str, int]:
        """Construye frecuencia de términos."""
        tf = defaultdict(int)
        for token in tokens:
            if token.token_type != TokenType.COMMENT:
                tf[token.value.lower()] += 1
        return dict(tf)

    def _extract_ngrams(self, tokens: List[CodeToken], n: int = 3) -> List[str]:
        """Extrae n-gramas de tokens."""
        values = [t.value for t in tokens if t.token_type != TokenType.COMMENT]
        ngrams = []
        for i in range(len(values) - n + 1):
            ngram = '_'.join(values[i:i+n])
            ngrams.append(ngram)
        return ngrams

    def _compute_structural_features(self, code: str) -> Dict[str, float]:
        """Calcula features estructurales del código."""
        features = {}

        # Contar elementos estructurales
        features['function_count'] = len(re.findall(r'\bfunction\s+\w+', code))
        features['modifier_count'] = len(re.findall(r'\bmodifier\s+\w+', code))
        features['event_count'] = len(re.findall(r'\bevent\s+\w+', code))
        features['require_count'] = len(re.findall(r'\brequire\s*\(', code))
        features['assert_count'] = len(re.findall(r'\bassert\s*\(', code))
        features['emit_count'] = len(re.findall(r'\bemit\s+\w+', code))

        # Métricas de complejidad
        features['loop_count'] = len(re.findall(r'\b(for|while|do)\s*\(', code))
        features['conditional_count'] = len(re.findall(r'\bif\s*\(', code))
        features['external_call_count'] = len(re.findall(r'\.(call|delegatecall|staticcall)\s*\(', code))

        # Normalizar por longitud
        code_lines = max(code.count('\n'), 1)
        for key in features:
            features[key] = features[key] / code_lines

        return features

    def _compute_security_features(self, code: str) -> Dict[str, float]:
        """Calcula features de seguridad."""
        features = {}
        code_lower = code.lower()

        # Patrones peligrosos
        features['has_selfdestruct'] = 1.0 if 'selfdestruct' in code_lower or 'suicide' in code_lower else 0.0
        features['has_delegatecall'] = 1.0 if 'delegatecall' in code_lower else 0.0
        features['has_tx_origin'] = 1.0 if 'tx.origin' in code_lower else 0.0
        features['has_inline_assembly'] = 1.0 if 'assembly' in code_lower else 0.0
        features['has_unchecked'] = 1.0 if 'unchecked' in code_lower else 0.0

        # Patrones seguros
        features['has_reentrancy_guard'] = 1.0 if 'nonreentrant' in code_lower else 0.0
        features['has_access_control'] = 1.0 if any(m.lower() in code_lower for m in ['onlyowner', 'onlyadmin', 'onlyrole']) else 0.0
        features['has_pausable'] = 1.0 if 'whennotpaused' in code_lower else 0.0
        features['uses_safemath'] = 1.0 if 'safemath' in code_lower else 0.0
        features['uses_openzeppelin'] = 1.0 if 'openzeppelin' in code_lower else 0.0

        # Ratio de seguridad
        dangerous = sum([
            features['has_selfdestruct'],
            features['has_delegatecall'],
            features['has_tx_origin'],
            features['has_inline_assembly'],
        ])
        safe = sum([
            features['has_reentrancy_guard'],
            features['has_access_control'],
            features['has_pausable'],
            features['uses_safemath'],
        ])
        features['security_ratio'] = safe / (dangerous + 1)

        return features

    def _compute_token_type_distribution(self, tokens: List[CodeToken]) -> Dict[str, float]:
        """Calcula distribución de tipos de tokens."""
        distribution = defaultdict(int)
        total = len(tokens) or 1

        for token in tokens:
            distribution[token.token_type.value] += 1

        return {k: v / total for k, v in distribution.items()}

    def embed(self, code: str, code_type: str = "unknown") -> CodeEmbedding:
        """
        Genera embedding para código Solidity.

        Args:
            code: Código fuente Solidity
            code_type: Tipo de código (function, contract, modifier)

        Returns:
            CodeEmbedding con vector de dimensión fija
        """
        tokens = self.tokenizer.tokenize(code)
        vector = []

        # 1. Features estructurales (20 dims)
        structural = self._compute_structural_features(code)
        struct_vector = [structural.get(k, 0.0) for k in sorted(structural.keys())]
        vector.extend(struct_vector[:20])
        while len(vector) < 20:
            vector.append(0.0)

        # 2. Features de seguridad (20 dims)
        security = self._compute_security_features(code)
        sec_vector = [security.get(k, 0.0) for k in sorted(security.keys())]
        vector.extend(sec_vector[:20])
        while len(vector) < 40:
            vector.append(0.0)

        # 3. Distribución de tipos de tokens (10 dims)
        token_dist = self._compute_token_type_distribution(tokens)
        type_names = ['keyword', 'type', 'modifier', 'function', 'variable',
                      'operator', 'literal', 'comment', 'other']
        for tname in type_names:
            vector.append(token_dist.get(tname, 0.0))
        vector.append(0.0)  # padding

        # 4. TF features para vocabulario común (40 dims)
        tf = self._build_vocabulary(tokens)
        common_terms = list(self.tokenizer.KEYWORDS)[:20] + list(self.tokenizer.TYPES)[:20]
        for term in common_terms:
            vector.append(min(tf.get(term.lower(), 0) / 10.0, 1.0))

        # 5. N-grama features (18 dims)
        ngrams = self._extract_ngrams(tokens, n=2)
        danger_patterns = [
            'call_value', 'transfer_msg', 'delegatecall', 'selfdestruct',
            'tx_origin', 'block_timestamp', 'assembly', 'unchecked',
            'external_call', 'low_level', 'require', 'assert', 'revert',
            'onlyowner', 'nonreentrant', 'payable', 'view', 'pure',
        ]
        for pattern in danger_patterns:
            count = sum(1 for ng in ngrams if pattern in ng.lower())
            vector.append(min(count / 5.0, 1.0))

        # 6. Métricas de código (20 dims)
        lines = code.count('\n') + 1
        chars = len(code)
        avg_line_len = chars / max(lines, 1)

        vector.append(min(lines / 500.0, 1.0))
        vector.append(min(chars / 10000.0, 1.0))
        vector.append(min(avg_line_len / 100.0, 1.0))
        vector.append(min(len(tokens) / 1000.0, 1.0))

        # Complejidad ciclomática aproximada
        complexity = (
            structural.get('conditional_count', 0) +
            structural.get('loop_count', 0)
        ) * lines
        vector.append(min(complexity / 50.0, 1.0))

        # Padding hasta embedding_dim
        while len(vector) < self.embedding_dim:
            vector.append(0.0)

        # Truncar si excede
        vector = vector[:self.embedding_dim]

        # Normalizar vector
        norm = math.sqrt(sum(v * v for v in vector))
        if norm > 0:
            vector = [v / norm for v in vector]

        return CodeEmbedding(
            source_hash=hashlib.sha256(code.encode()).hexdigest()[:16],
            vector=vector,
            dimensions=self.embedding_dim,
            tokens=len(tokens),
            code_type=code_type,
            metadata={
                'lines': lines,
                'structural': structural,
                'security': security,
            },
        )

    def embed_function(self, code: str, function_name: str) -> Optional[CodeEmbedding]:
        """Extrae y embebe una función específica."""
        # Buscar la función
        pattern = rf'function\s+{re.escape(function_name)}\s*\([^)]*\)[^{{]*\{{'
        match = re.search(pattern, code)

        if not match:
            return None

        # Extraer cuerpo de la función
        start = match.start()
        brace_count = 0
        end = start

        for i, char in enumerate(code[start:], start):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end = i + 1
                    break

        function_code = code[start:end]
        return self.embed(function_code, code_type="function")

    def find_similar(
        self,
        target: CodeEmbedding,
        candidates: List[CodeEmbedding],
        threshold: float = 0.7,
    ) -> List[Tuple[CodeEmbedding, float]]:
        """Encuentra embeddings similares al target."""
        similar = []

        for candidate in candidates:
            if candidate.source_hash == target.source_hash:
                continue

            similarity = target.similarity(candidate)
            if similarity >= threshold:
                similar.append((candidate, similarity))

        # Ordenar por similitud descendente
        similar.sort(key=lambda x: -x[1])
        return similar


class VulnerabilityPatternDB:
    """Base de datos de patrones de vulnerabilidad conocidos."""

    def __init__(self, embedder: Optional[CodeEmbedder] = None):
        self.embedder = embedder or CodeEmbedder()
        self._patterns: Dict[str, List[CodeEmbedding]] = {}
        self._initialize_patterns()

    def _initialize_patterns(self) -> None:
        """Inicializa patrones de vulnerabilidad conocidos."""
        # Patrón de reentrancy
        reentrancy_code = """
        function withdraw(uint256 amount) external {
            require(balances[msg.sender] >= amount);
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
            balances[msg.sender] -= amount;
        }
        """
        self._patterns['reentrancy'] = [
            self.embedder.embed(reentrancy_code, 'vulnerability')
        ]

        # Patrón de tx.origin
        txorigin_code = """
        function transferTo(address to, uint amount) public {
            require(tx.origin == owner);
            to.transfer(amount);
        }
        """
        self._patterns['tx_origin'] = [
            self.embedder.embed(txorigin_code, 'vulnerability')
        ]

        # Patrón de unchecked return
        unchecked_code = """
        function transfer(address to, uint amount) public {
            token.transfer(to, amount);
            emit Transfer(to, amount);
        }
        """
        self._patterns['unchecked_return'] = [
            self.embedder.embed(unchecked_code, 'vulnerability')
        ]

        # Patrón de integer overflow (pre-0.8)
        overflow_code = """
        function add(uint a, uint b) public pure returns (uint) {
            return a + b;
        }
        """
        self._patterns['overflow'] = [
            self.embedder.embed(overflow_code, 'vulnerability')
        ]

        # Patrón de access control missing
        access_code = """
        function setOwner(address newOwner) public {
            owner = newOwner;
        }
        """
        self._patterns['missing_access_control'] = [
            self.embedder.embed(access_code, 'vulnerability')
        ]

    def match_patterns(
        self,
        code: str,
        threshold: float = 0.6,
    ) -> List[Dict[str, Any]]:
        """Busca patrones de vulnerabilidad en código."""
        embedding = self.embedder.embed(code)
        matches = []

        for vuln_type, patterns in self._patterns.items():
            for pattern in patterns:
                similarity = embedding.similarity(pattern)
                if similarity >= threshold:
                    matches.append({
                        'vulnerability_type': vuln_type,
                        'similarity': round(similarity, 3),
                        'confidence': round(min(similarity * 1.2, 0.95), 3),
                    })

        # Ordenar por similitud
        matches.sort(key=lambda x: -x['similarity'])
        return matches

    def add_pattern(
        self,
        vuln_type: str,
        code: str,
    ) -> None:
        """Añade un nuevo patrón de vulnerabilidad."""
        embedding = self.embedder.embed(code, 'vulnerability')
        if vuln_type not in self._patterns:
            self._patterns[vuln_type] = []
        self._patterns[vuln_type].append(embedding)
