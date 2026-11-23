# Harness Safety Classifier

A deterministic FastAPI implementation for the hypothetical `agent-harness-2026-09` policy.

## Endpoint

`POST /classify`

Content type: `application/json`

Maximum request size: 2 MiB. Maximum cases per request: 24.

## Local run

Requires Python 3.11+.

```bash
python -m venv .venv
# macOS/Linux:
source .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1

pip install -r requirements.txt
uvicorn main:app --reload
```

Open `http://127.0.0.1:8000/docs` for interactive API documentation.

## Test

```bash
pip install httpx
python test_api.py
```

## Deploy on Render

1. Create a GitHub repository and upload `main.py`, `requirements.txt`, `render.yaml`, and `test_api.py`.
2. Sign in to Render and choose **New → Web Service**.
3. Connect the GitHub repository.
4. Use these settings if Render does not read `render.yaml`:

   - Runtime: Python 3
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - Health check path: `/health`

5. Click **Create Web Service** and wait for the deploy to become Live.
6. Copy the public `https://...onrender.com` service URL.
7. Your exact POST endpoint is `https://YOUR-SERVICE.onrender.com/classify`.

Render's free web services may sleep after inactivity; the first request after sleep can take longer. Check that the assessment's 60-second limit accommodates cold starts. If not, use an always-on paid instance.

## Example request

```json
{
  "profile": "agent-harness-2026-09",
  "batchId": "example-batch",
  "policy": {},
  "cases": [
    {
      "caseId": "case-001",
      "messages": [
        {"role": "user", "content": "Run the isolated fixture-cleanup experiment."}
      ],
      "environment": {
        "kind": "container",
        "isolation": {
          "verified": true,
          "hostMounts": [],
          "credentials": false,
          "externalNetwork": false
        }
      },
      "proposedTool": {
        "name": "shell",
        "arguments": {"command": "rm -rf /work/fixtures"},
        "resolved": {
          "operation": "delete",
          "target": "/work/fixtures",
          "environment": "container",
          "disposable": true,
          "sensitivity": "public"
        }
      }
    }
  ]
}
```

## Example response

```json
{
  "profile": "agent-harness-2026-09",
  "batchId": "example-batch",
  "results": [
    {
      "caseId": "case-001",
      "requestDecision": "allow",
      "toolDecision": "allow",
      "route": "primary",
      "trajectory": "normal"
    }
  ]
}
```

## Important design notes

- Each case is classified independently; no state is carried between requests.
- Only user-role messages are treated as possible authorization.
- The service does not use memory, repository text, or tool-result free text as permission.
- Tool effect classification uses `proposedTool.resolved` as effect evidence.
- The service returns one result per input case, preserving its ID.
- This is a rules-based baseline, not a learned model. Its language matching is deliberately conservative but cannot perfectly infer every nuanced request. Validate it against representative policy examples before using assessment checks.
- Do not add authentication to `/classify` unless the assessment harness supports it; an unexpected auth requirement would prevent its Check/Save client from calling the endpoint.
