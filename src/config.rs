// THIS FILE INTENTIONALLY CONTAINS A FAKE SECRET FOR TESTING
// In a real codebase, this is exactly the kind of mistake TruffleHog catches.

/// Database configuration
pub struct Config {
    pub database_url: String,
    pub private_key: String,
}

impl Config {
    pub fn load() -> Self {
        Config {
            database_url: "postgres://admin:SuperSecret123!@db.production.internal:5432/myapp".to_string(),

            // Oops! Someone pasted a private key directly in code
            private_key: "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDHjprOOJ3tpWO4
1Ez5kqtNjs3eYdnD/EEMTqiBubT4smEXjIa8l/pfGo+JPwnkn8tjDaq3QUg3RS39
ty3aJGpm614a6yZsGMxoaMhY/a4pJFL6gHznrSrzGL2qZckToKbOQsbRx7KiPNQc
W/UfbF7CXWWiwahgiZpT8FByaVND3sc2LPtnOlDMmTFtVShzywIe13xllTNccn3A
T7iX1rskSZ9aKnBlkiCp77SVJbimSSKQRtOeNLaWdSNFrYpX1wC3XOHeLqrmIEZe
Gahk2AF5fHTI36GaDUc1HC83uZJQq3ShG/nDliLFuipOECTceG6vZg5hFABkggek
Ekyz1DdzAgMBAAECggEAKdQZXMp/R/XX3kEZ1WJJ59rcChYGmE8Cr3q5VV/AsDRr
p4z8HQHaKB8gIQuGnlZkQmH1+62CXptwlXLU+JmTd/kz436Qsi3MgsIb5JNf8x27
CujtxX4Ft6ji8JmfOS7+Z9OVaxlptxn69+rKiYikoCcFi8T97yZIo/mGU0UCgAIO
Rtz5V/Cf78uXGWd7hTClSINHEtstR7/sBPiQlKHsdnU7CUNi6AAwNBMlBmzSA9H4
HeOKLF6iu2jVzjdTHbhQg7bSqKUrIrT3YtNJhQjVEbqwdDdkSJlPP/8b7Il4RTBL
4BRgCK4XWUSXgMC2fIP6UjphbcbXOSzU7qWb3her8QKBgQDz2JF/DNYZHKARxfad
3PCtLb+UEaEYiAytAsycYjcCuX4Pdf9/0oWKiAMQClcJDVCWcDYmwB5UFwXHU09v
KhYaqNF0CmZWwYH2i6g5lT/ia0NoCmJ3C3zpsDP9h8yyRHr9ij2+nvywnpnEIz0Z
Rq948ShBhwz2zRzeTY1ckXUQqwKBgQDRgOrjmNcz5YEEk3lcFJXkbzqKYeNxHWPv
/pibCoKI8dX9KZQGHDT3aBAkX4m05ZU9BNg57HDI/m1qwuGTV28LvOUY+EGKPr5w
LXwt5XwXVHJx05GjPhVfMNDJ/E5c1tyaV1yneMsqar0ExSl+BfbASrR6uIPqfOmk
MePNpRxEWQKBgD76KemkSQ9HQ1gTxrPSwh4X+KinPPH3AT8Vv/6LpyV+/r3Dfe9n
UbILmq7j3MKru6p+5J1xdOPG5mkqbROKzRapjx7nKLMzWvtv6kyk7VDu3wPZ2sBg
KSy5o1PRZN6NrS4aLAQ1T5HWBGSRrU//34Xe0sTJumFrbA9F/EJyFsftAoGAXkcZ
bNp23Y/GA30p+9n3qhizy1pJs7l6I6H6oqqUG3RYy9hOGIHRBBT8TqH/ojw+cHsh
os9X4ds8+fJA+ME745hZsGbnd4LMyEZvv2ep9AW4iqievUtO6stY6cx0pyq5k2sE
8whUxP3Lmb3v8hpU9CuqFB+8nWUg7xbUYNKQaeECgYEAh535RHr2wlqAom+YiioD
ccRFvfmvDl6j/FwP/I5kpAW6eb5dJlG+5IiBzhUVMJXsH8OqoDuHuEccGnSkIUhL
NbgBDnks7HtTIWfNigquhPsTWdl932pmy9ETbMob03PfB2M3CAKX0aRIbfeCLqWn
Gt3HvDft8HjZ9jwEhPaQ87Y=
-----END PRIVATE KEY-----".to_string(),
        }
    }
}
