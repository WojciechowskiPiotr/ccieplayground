from OpenSSL import crypto
import boto3
from botocore.exceptions import ClientError


def createCertificate(req, issuerCert, issuerKey, serial, notBefore, notAfter, digest="sha256"):
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerCert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())

    cert.add_extensions((
        crypto.X509Extension(b'basicConstraints', False,
                             b'CA:FALSE'),
        crypto.X509Extension(b'keyUsage', True,
                             b'digitalSignature, keyEncipherment'),
        crypto.X509Extension(
            b'authorityKeyIdentifier', False, b'keyid:always', issuer=issuerCert),
        crypto.X509Extension(
            b'extendedKeyUsage', False, b'serverAuth, clientAuth')
    ))

    cert.sign(issuerKey, digest)
    return cert


def main(event, context):
    s3 = boto3.resource('s3')

    try:
        ca_cert_s3obj = s3.Object('certsigninglambdabucket','signing-ca.crt')
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_s3obj.get()['Body'].read())
    except ClientError as e:
        print(e.message)

    try:
        ca_key_s3obj = s3.Object('certsigninglambdabucket','root-ca.key')
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key_s3obj.get()['Body'].read(), b'test')
    except ClientError as e:
        print(e.message)

    try:
        crt_req_s3obj = s3.Object('certsigninglambdabucket', 'asav-3.virl.lan.crt.csr')
        crt_req = crypto.load_certificate_request(crypto.FILETYPE_PEM, crt_req_s3obj.get()['Body'].read())
    except ClientError as e:
        print(e.message)

    new_crt_serial = 990099

    new_crt = createCertificate(
        crt_req, ca_cert, ca_key, new_crt_serial, 0, 230400)

    msgCertificateParameters = crypto.dump_certificate(crypto.FILETYPE_TEXT, new_crt)
    print(msgCertificateParameters.decode('utf-8'))
    msgCertificateParameters = crypto.dump_certificate(crypto.FILETYPE_PEM, new_crt)
    print(msgCertificateParameters.decode('utf-8'))

    try:
        s3.Object('certsigninglambdabucket','asav-3.virl.lan.crt').put(Body=crypto.dump_certificate(crypto.FILETYPE_PEM, new_crt))
    except ClientError as e:
        print(e.message)

    return
