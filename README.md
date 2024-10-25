# goddbproxy  

DynamoDB와 프로그램 사이에서 뭔가를 하는 프로그램\
A program that does something between DynamoDB and your program

```bash
# goddbproxy [-f configfile] [-c]

# create config file
$ goddbproxy -c

# edit config file
$ vim config.toml

# run
$ goddbproxy
```

## 동작 설명 (Behavior Description)

DynamoDB Local에 접속할 EndPoint를 아래와 같이 설정한다.\
Set the EndPoint to connect to DynamoDB Local.

`https://ddb.example.com:8001/username/secret`

DynamoDB Local은 아래와 같은 이름의 sqlite3 파일을 생성한다.\
DynamoDB Local creates a sqlite3 file with the following name.

`username_region.db`

예를 들어 username이 bs이고 region이 us-east-1인 경우\
For example, if the username is bs and the region is us-east-1

`bs_us-east-1.db`

config.yaml의 Users에 설정한 username과 secret으로 요청한 path가 일치하고\
요청 헤더가 username이 access key id인 경우 접근을 허용한다.\
If the requested path matches the username and secret set in Users and the request header is username as access key id, access is allowed.

개인적으로 사용할 목적의 작은 DB로는 충분히 사용할 수 있다.\
It can be used as a small DB for personal use.

추후에 대용량 DB가 필요해지면 클라이언트의 접속 부분만 수정해서 AWS DynamoDB로 변경하면 된다.\
Later, when a large DB is needed, you can modify only the client connection part to AWS DynamoDB.

## API Request Example

DescribeTable

```yaml
body:
    TableName: tablename
header:
    Authorization:
        - AWS4-HMAC-SHA256 Credential=accessid/20241025/us-east-1/dynamodb/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-target, Signature=...
    Connection:
        - close
    Content-Length:
        - "24"
    Content-Type:
        - application/x-amz-json-1.0
    User-Agent:
        - aws-sdk-nodejs/2.1691.0 win32/v20.10.0 promise
    X-Amz-Content-Sha256:
        - ...
    X-Amz-Date:
        - 20241025T135347Z
    X-Amz-Target:
        - DynamoDB_20120810.DescribeTable
host: localhost:21002
method: POST
remote: 127.0.0.1:53450
requestURI: /
url: /
```

## 참고 (Reference)

- [DynamoDB Local](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html)
  - java는 OpenJDK 17이상이면 된다.
  - 기본적인 실행방법
    ```bash
    $ java -Djava.library.path=./DynamoDBLocal_lib -jar DynamoDBLocal.jar -cors "*" -dbPath ".\dbfiles" -port 21000
    ```