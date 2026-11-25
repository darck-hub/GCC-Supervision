FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GCC_HOST=0.0.0.0 \
    GCC_PORT=8443

# Utilisateur dédié sans privilèges (principe du moindre privilège ANSSI)
RUN groupadd --gid 10001 gccgroup && \
    useradd --uid 10001 --gid gccgroup --create-home --shell /usr/sbin/nologin gccuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=gccuser:gccgroup backend ./backend
COPY --chown=gccuser:gccgroup frontend ./frontend
COPY --chown=gccuser:gccgroup scripts ./scripts

RUN mkdir -p /app/data /app/certs && chown -R gccuser:gccgroup /app/data /app/certs

USER gccuser

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import ssl, urllib.request; ctx=ssl._create_unverified_context(); urllib.request.urlopen('https://127.0.0.1:8443/api/health', context=ctx)" || exit 1

CMD ["python", "-m", "backend.app"]
