
FROM golang:alpine AS build
LABEL maintainer "Abdullah Saleem <a.saleem2993@gmail.com>"
RUN apk update && apk upgrade && apk add --no-cache bash git openssh
RUN mkdir -p /go/src/github.com/abdullah2993/socks5-server
WORKDIR /go/src/github.com/abdullah2993/socks5-server
COPY . /go/src/github.com/abdullah2993/socks5-server
RUN go get ./...
RUN go build -o socks5-server

FROM alpine
LABEL maintainer "Abdullah Saleem <a.saleem2993@gmail.com>"
RUN mkdir app
ENV PATH /app:$PATH
COPY --from=build /go/src/github.com/abdullah2993/socks5-server/socks5-server /app/
EXPOSE 5555
ENTRYPOINT [ "socks5-server" ]