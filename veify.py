from asn1crypto import cms, pem


with open('Свидетельство Купсик К.Г. ГИП И.pdfSGN1.sig', 'rb') as f:
    sig_data = f.read()

if pem.detect(sig_data):
    _, _, sig_data = pem.unarmor(sig_data)

content_info = cms.ContentInfo.load(sig_data)

if content_info['content_type'].native != 'signed_data':
    raise ValueError('No SigneData')

signed_data = content_info['content']

certs = signed_data['certificates']
if not certs:
    raise ValueError('Сертификатов не найдено в .sig')

cert = certs[0].chosen
with open('extracted_sert.der', 'wb') as f:
    f.write(cert.dump())