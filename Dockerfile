FROM golang:1.27-alpine

RUN apk add --no-cache make git upx zip

WORKDIR /src
COPY . .

RUN make deploy VERSION=docker

CMD ["sh", "-c", "cp -r out/* /go/bin/"]
