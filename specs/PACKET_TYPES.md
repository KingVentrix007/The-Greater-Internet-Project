GET_RSA:
VERSION:HTTPE/{version}
TYPE:GET_RSA
METHOD:POST
END

SHARE_AES:
VERSION:HTTPE/{version}
TYPE:SHARE_AES
METHOD:POST
HEADERS:
user_id:{user_id}
aes_key:{aes_key}
END

REQ_ENC:
VERSION:HTTPE/{version}
TYPE:REQ_ENC
TOKEN:{token}
//AES Encrypted
METHOD:{method}
LOCATION:{location}
HEADERS:
client_id
packet_id
is_com_setup:{unused,}
timestamp
compressions
//
END

REQ_END
VERSION:HTTPE/{version}
TYPE:REQ_END
TOKEN:{token}
//AES Encrypted
HEADERS:
client_id
packet_id
is_com_setup:{unused,}
timestamp
compressions
//
END
