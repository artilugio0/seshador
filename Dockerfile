FROM golang:1.25.7-trixie

RUN apt-get update && apt-get upgrade -y
RUN go install fyne.io/tools/cmd/fyne@latest

RUN go env -w GOFLAGS=-buildvcs=false

RUN mkdir /app
WORKDIR /app
