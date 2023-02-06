FROM golang:1.19

WORKDIR /app
COPY go.mod go.sum /app/
RUN go mod download
COPY . /app/

RUN go build -o id-sea main.go

ENTRYPOINT [ "/app/id-sea" ]