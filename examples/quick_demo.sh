#!/bin/bash
# MIESC Quick Demo - 2 minutos
# Para cuando hay poco tiempo en la defensa

set -e

echo ""
echo "=== MIESC v4.0.0 - Quick Demo ==="
echo ""

echo "[1/4] Version y herramientas..."
miesc version
echo ""

echo "[2/4] Verificando herramientas..."
miesc doctor
echo ""

echo "[3/4] Analizando contrato vulnerable..."
echo "Contrato: VulnerableBank.sol (Reentrancy)"
miesc scan contracts/audit/VulnerableBank.sol 2>&1 | head -50 || true
echo ""

echo "[4/4] Demo completada!"
echo ""
echo "Comandos disponibles:"
echo "  miesc scan <file>   - Analisis rapido"
echo "  miesc audit <file>  - Auditoria 7 capas"
echo "  miesc api           - Servidor REST"
echo "  miesc doctor        - Check herramientas"
echo ""
