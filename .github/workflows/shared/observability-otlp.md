---
observability:
  otlp:
    endpoint: ${{ secrets.GH_AW_OTEL_ENDPOINT }}
    headers:
      Authorization: ${{ secrets.GH_AW_OTEL_HEADERS }}
---
