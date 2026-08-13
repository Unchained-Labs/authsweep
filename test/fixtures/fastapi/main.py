from fastapi import FastAPI, Depends
from .auth import current_user, require_admin

app = FastAPI()

@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.get("/me")
def me(user = Depends(current_user)):
    return user

@app.delete("/admin/tenants/{tenant_id}")
def drop_tenant(tenant_id: str, _admin = Depends(require_admin)):
    return delete_tenant(tenant_id)

# REAL GAPS
@app.post("/billing/refund")
def refund(payload: dict):
    return issue_refund(payload)

@app.get("/users/{user_id}/secrets")
def secrets(user_id: str):
    return load_secrets(user_id)

@app.patch("/settings")
def settings(payload: dict):
    return save(payload)
