FROM golang:1.20

WORKDIR /app

COPY . .

RUN go get -d -v ./...
RUN go build -o bin/auth_api.exe ./cmd
RUN [ "chmod", "+x", "/app/bin/auth_api.exe"]

ENTRYPOINT [ "./bin/auth_api.exe" ]

EXPOSE 7777
