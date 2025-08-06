import binascii
from asn1crypto import cms
from gostcrypto.gosthash import gost_34_11_2012
from gostcrypto.gostsignature import gost_34_10_2012



def extract_cert(sig_path):
    with open(sig_path, "rb") as f:
        sig_data = f.read()
    content_info = cms.ContentInfo.load(sig_data)
    if content_info['content_type'].native != 'signed_data':
        raise ValueError("Файл не содержит CMS")
    signed_data = content_info['content']
    certs = signed_data['certificates']
    if not certs:
        raise ValueError("В .sig не найдено сертификатов")
    cert = certs[0].chosen
    return cert


def extract_pubkey_from_cert(cert):
    pubkey_bits = cert['tbs_certificate']['subject_public_key_info']['public_key'].native
    if len(pubkey_bits) != 64:
        raise ValueError("Подпись не 64 байта")
    Qx = pubkey_bits[:32]
    Qy = pubkey_bits[32:]
    return Qx, Qy


def extract_signature(sig_path):
    with open(sig_path, "rb") as f:
        sig_data = f.read()
    content_info = cms.ContentInfo.load(sig_data)
    signed_data = content_info['content']
    signer_infos = signed_data['signer_infos']
    if len(signer_infos) == 0:
        raise ValueError("Нет информации")
    signature_bytes = signer_infos[0]['signature'].native
    if len(signature_bytes) != 64:
        raise ValueError("Подпись не 64 байта")
    r = signature_bytes[:32]
    s = signature_bytes[32:]
    return r, s


def verify_signature(pdf_path, sig_path):
    with open(pdf_path, "rb") as f:
        data = f.read()

    cert = extract_cert(sig_path)
    Qx, Qy = extract_pubkey_from_cert(cert)
    r, s = extract_signature(sig_path)

    params = gost_34_10_2012.get_paramset("id-tc26-gost-3410-12-256-paramSetA")
    pub_key = gost_34_10_2012.public_key(Qx, Qy, params)

    digest = gost_34_11_2012.new(data).digest()

    valid = gost_34_11_2012.verify(pub_key, digest, r, s)
    return valid


if __name__ == "__main__":
    pdf_path = "Свидетельство Купсик К.Г. ГИП И.pdf.pdf"
    sig_path = "Свидетельство Купсик К.Г. ГИП И.pdfSGN1.sig"

    try:
        is_valid = verify_signature(pdf_path, sig_path)
        if is_valid:
            print("Подпись действительна")
        else:
            print("Подпись не действительна")
    except Exception as e:
        print(f"Ошибка: {e}")