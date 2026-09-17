FROM python:3.12

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV TICKETDESK_JWKS_URL=http://keycloak:8080/realms/ticketdesk/protocol/openid-connect/certs
ENV TICKETDESK_ISSUER=http://keycloak:8080/realms/ticketdesk
ENV TICKETDESK_USER=alice
ENV TICKETDESK_GROUPS=eng

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
