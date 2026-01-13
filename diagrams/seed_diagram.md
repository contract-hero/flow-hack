```mermaid
flowchart LR
    A[Real tokens] -->|"move (<-)"| B[Wrap in ResourceWrapper]
    B -->|"move (<-)"| C[Deploy NFTPoolInstance0]
    C --> D[Pool holds real tokens]
```
