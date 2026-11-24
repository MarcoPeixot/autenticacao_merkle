# Experimento multi-alvo: resultado bruto

Gerado por `python3 -m tools.experimento_multialvo --gravar`. A leitura do resultado está em `docs/hipoteses.md`.

Hash truncado a 14 bits, 64 módulos por árvore, 1048576 tentativas por esquema. Com um alvo só, o esperado é 64 provas aceitas. O ganho é quantas vezes as aceitas passam disso. As aceitas por acaso fecham por outra coincidência no caminho e não entram no ganho.

| Esquema | Árvores | Nós comparados | Coincidências | Recusadas pelo tamanho | Recusadas pelo caminho | Aceitas | Ganho | Aceitas por acaso |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| patch | 1 | 63 | 4001 | 1989 | 1950 | 62 | 1,0 | 0 |
| patch | 4 | 252 | 16115 | 7990 | 7864 | 259 | 4,0 | 2 |
| patch | 16 | 1008 | 64175 | 31732 | 31354 | 1077 | 16,8 | 12 |
| folha sem posição | 1 | 63 | 4068 | 2008 | 0 | 2060 | 32,2 | 0 |
| folha sem posição | 4 | 252 | 16170 | 7960 | 0 | 8210 | 128,3 | 0 |
| folha sem posição | 16 | 1008 | 64539 | 31738 | 0 | 32801 | 512,5 | 0 |
| folha com árvore | 1 | 63 | 4071 | 2063 | 1939 | 69 | 1,1 | 0 |
| folha com árvore | 4 | 252 | 16015 | 7941 | 8002 | 69 | 1,1 | 3 |
| folha com árvore | 16 | 1008 | 64166 | 31582 | 32504 | 69 | 1,1 | 11 |

Subárvore falsa mais alta, só no esquema do patch:

| Esquema | Árvores | Nós comparados | Coincidências | Recusadas pelo tamanho | Recusadas pelo caminho | Aceitas | Ganho | Aceitas por acaso |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| patch, altura 2 | 1 | 63 | 3983 | 3004 | 916 | 62 | 1,0 | 1 |
| patch, altura 2 | 4 | 252 | 16120 | 12091 | 3769 | 259 | 4,0 | 1 |
| patch, altura 2 | 16 | 1008 | 64755 | 48277 | 15443 | 1029 | 16,1 | 6 |
| patch, altura 3 | 1 | 63 | 4018 | 3505 | 441 | 72 | 1,1 | 0 |
| patch, altura 3 | 4 | 252 | 16181 | 14138 | 1766 | 277 | 4,3 | 0 |
| patch, altura 3 | 16 | 1008 | 64335 | 56082 | 7198 | 1055 | 16,5 | 0 |
