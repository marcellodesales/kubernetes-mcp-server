FROM --platform=$BUILDPLATFORM golang:1.26.3 AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /app
COPY ./ ./

RUN make build-multiarch TARGETOS=${TARGETOS} TARGETARCH=${TARGETARCH}

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest
LABEL io.modelcontextprotocol.server.name="io.github.containers/kubernetes-mcp-server"
WORKDIR /app
COPY --from=builder /app/kubernetes-mcp-server /app/kubernetes-mcp-server

# Provide a writable HOME for the non-root user (required for kubeconfig bootstrap).
ENV HOME=/home/nonroot
RUN mkdir -p "${HOME}/.kube" && chown -R 65532:65532 "${HOME}"

USER 65532:65532
ENV KUBECONFIG="${HOME}/.kube/config"
ENTRYPOINT ["/app/kubernetes-mcp-server"]
CMD ["--port", "8080"]
EXPOSE 8080
