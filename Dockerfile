# hadolint ignore=DL3007
FROM gitlab.contabo.intra:5050/arcus/common/images/base-images/runtime/init-container:latest

COPY target/*.jar /app/
