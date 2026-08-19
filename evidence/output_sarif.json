{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "MIESC",
          "version": "4.1.0",
          "informationUri": "https://github.com/fboiero/miesc",
          "rules": [
            {
              "id": "MIESC-REENTRANCY",
              "name": "Reentrancy",
              "shortDescription": {
                "text": "Reentrancy Vulnerability"
              },
              "fullDescription": {
                "text": "External call before state update allows reentrancy attack"
              },
              "defaultConfiguration": {
                "level": "error"
              },
              "properties": {
                "tags": [
                  "security",
                  "smart-contract",
                  "layer-1"
                ],
                "precision": "high",
                "cwe": "CWE-841",
                "swc": "SWC-107"
              },
              "help": {
                "text": "Use ReentrancyGuard or checks-effects-interactions pattern",
                "markdown": "## Remediation\n\nUse ReentrancyGuard or checks-effects-interactions pattern"
              }
            },
            {
              "id": "MIESC-OVERFLOW",
              "name": "Overflow",
              "shortDescription": {
                "text": "Integer Overflow"
              },
              "fullDescription": {
                "text": "Arithmetic operation may overflow"
              },
              "defaultConfiguration": {
                "level": "error"
              },
              "properties": {
                "tags": [
                  "security",
                  "smart-contract",
                  "layer-3"
                ],
                "precision": "high",
                "cwe": "CWE-190"
              },
              "help": {
                "text": "Use SafeMath or Solidity 0.8.x built-in overflow checks",
                "markdown": "## Remediation\n\nUse SafeMath or Solidity 0.8.x built-in overflow checks"
              }
            },
            {
              "id": "MIESC-UNCHECKED-CALL",
              "name": "Unchecked Call",
              "shortDescription": {
                "text": "Unchecked Return Value"
              },
              "fullDescription": {
                "text": "Return value of low-level call not checked"
              },
              "defaultConfiguration": {
                "level": "warning"
              },
              "properties": {
                "tags": [
                  "security",
                  "smart-contract",
                  "layer-1"
                ],
                "precision": "high",
                "cwe": "CWE-252"
              },
              "help": {
                "text": "Check return value or use require()",
                "markdown": "## Remediation\n\nCheck return value or use require()"
              }
            },
            {
              "id": "MIESC-GAS",
              "name": "Gas",
              "shortDescription": {
                "text": "Gas Optimization"
              },
              "fullDescription": {
                "text": "Loop can be optimized to save gas"
              },
              "defaultConfiguration": {
                "level": "note"
              },
              "properties": {
                "tags": [
                  "security",
                  "smart-contract",
                  "layer-1"
                ],
                "precision": "medium"
              },
              "help": {
                "text": "Cache array length outside loop",
                "markdown": "## Remediation\n\nCache array length outside loop"
              }
            }
          ],
          "properties": {
            "layers": 7,
            "techniques": [
              "static-analysis",
              "fuzzing",
              "symbolic-execution",
              "formal-verification",
              "ai-analysis",
              "ml-detection",
              "correlation"
            ]
          }
        }
      },
      "results": [
        {
          "ruleId": "MIESC-REENTRANCY",
          "level": "error",
          "message": {
            "text": "External call before state update allows reentrancy attack"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "contracts/Vault.sol",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "startLine": 42,
                  "endLine": 48,
                  "startColumn": 8
                }
              }
            }
          ],
          "fingerprints": {
            "primaryLocationLineHash": "efb307fa7afecc80"
          },
          "properties": {
            "confidence": 0.95,
            "tool": "slither",
            "layer": 1
          },
          "partialFingerprints": {
            "primaryLocationLineHash": "efb307fa7afecc80"
          }
        },
        {
          "ruleId": "MIESC-OVERFLOW",
          "level": "error",
          "message": {
            "text": "Arithmetic operation may overflow"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "contracts/Token.sol",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "startLine": 156,
                  "startColumn": 12
                }
              }
            }
          ],
          "fingerprints": {
            "primaryLocationLineHash": "7b0dcdd343782039"
          },
          "properties": {
            "confidence": 0.88,
            "tool": "mythril",
            "layer": 3
          },
          "partialFingerprints": {
            "primaryLocationLineHash": "7b0dcdd343782039"
          }
        },
        {
          "ruleId": "MIESC-UNCHECKED-CALL",
          "level": "warning",
          "message": {
            "text": "Return value of low-level call not checked"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "contracts/Utils.sol",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "startLine": 78
                }
              }
            }
          ],
          "fingerprints": {
            "primaryLocationLineHash": "d4e1757a7e950740"
          },
          "properties": {
            "confidence": 0.82,
            "tool": "slither",
            "layer": 1
          },
          "partialFingerprints": {
            "primaryLocationLineHash": "d4e1757a7e950740"
          }
        },
        {
          "ruleId": "MIESC-GAS",
          "level": "note",
          "message": {
            "text": "Loop can be optimized to save gas"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "contracts/Staking.sol",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "startLine": 234
                }
              }
            }
          ],
          "fingerprints": {
            "primaryLocationLineHash": "d5d5eb42baf0c21d"
          },
          "properties": {
            "confidence": 0.75,
            "tool": "aderyn",
            "layer": 1
          },
          "partialFingerprints": {
            "primaryLocationLineHash": "d5d5eb42baf0c21d"
          }
        }
      ],
      "invocations": [
        {
          "executionSuccessful": true,
          "endTimeUtc": "2025-12-13T21:38:35.806533Z"
        }
      ]
    }
  ]
}