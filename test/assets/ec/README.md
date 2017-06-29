# Elliptic Curve Keys for Unit Testing

Generate private key:

    openssl genpkey -out private_key.pem -algorithm EC \
      -pkeyopt ec_paramgen_curve:prime256v1 \
      -pkeyopt ec_param_enc:named_curve
