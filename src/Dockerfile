FROM dhi.io/golang:1.27-dev AS build-stage

WORKDIR /app

COPY ./src/go.mod ./src/go.sum ./
RUN go mod download

COPY ./src .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /dns-scanner .

FROM dhi.io/static:20250419-debian13 AS runtime-stage

WORKDIR .

COPY --from=build-stage /dns-scanner /dns-scanner

EXPOSE 10000

USER 65532:65532

ENTRYPOINT ["/dns-scanner"]
