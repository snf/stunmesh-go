FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go embedca.go ./
COPY app/ app/
COPY internal/ internal/
COPY mobile/ mobile/
COPY pluginapi/ pluginapi/
RUN CGO_ENABLED=0 go build -trimpath -tags embedca -ldflags='-s -w' -o /out/stunmesh-go .

FROM scratch
COPY --from=build /out/stunmesh-go /stunmesh-go
ENTRYPOINT ["/stunmesh-go"]
