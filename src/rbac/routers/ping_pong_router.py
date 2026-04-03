from fastapi import APIRouter

router = APIRouter(
    tags=["Healthcheck"],
)


@router.get("/ping")
async def ping_pong() -> str:
    return "pong"
