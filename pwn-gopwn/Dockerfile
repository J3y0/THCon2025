FROM golang:1.24

WORKDIR /usr/app

COPY go.mod ./

COPY gopwn.go ./
RUN CGO_ENABLED=1 go build -v -o ./bin/gopwn .

COPY flag.txt ./

EXPOSE 4000

CMD [ "/usr/app/bin/gopwn" ]
