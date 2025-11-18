import json
import os
from PIL import Image
from django.http import Http404, HttpResponse
from django.http.response import JsonResponse, StreamingHttpResponse
from django.views.decorators.csrf import csrf_exempt
from pylibdmtx.pylibdmtx import encode
from reportlab.pdfgen import canvas
import time
import random
from pathlib import Path
from .forms import UploadForm
from cryptography import x509
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import urllib.request
from datetime import date, datetime
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from api.serializers import *
from rest_framework.renderers import JSONRenderer
from rest_framework.decorators import api_view, permission_classes, renderer_classes
from lxml import etree
import re

BASE_DIR = Path(__file__).resolve().parent.parent


@csrf_exempt
@api_view(['POST'])
@renderer_classes([JSONRenderer])
@permission_classes([IsAuthenticated])
def get_cev(request, size):
    if request.method == 'POST':
        encoded = encode(size.encode('utf8'), scheme='C40')
        img = Image.frombytes(
            'RGB', (encoded.width, encoded.height), encoded.pixels)
        current_time = time.time()
        random_number = random.randint(1, 1000000)
        base_dir = os.path.join(BASE_DIR, 'CEVs')
        image_name = str(current_time) + '-' + str(random_number)+'.png'
        img.save(os.path.join(base_dir, image_name))
        contenu = {
            "filename": image_name
        }
        response = JsonResponse(contenu)
        response.status_code = 200
        return response


class revoked(APIView):
    permission_classes = (IsAuthenticated,)
    renderer_classes = [JSONRenderer]

    def post(self, request, *args, **kwargs):
        cn = kwargs['cn']
        with urllib.request.urlopen('https://public.qcdigitalhub.com/crl/csca.crl') as file:
            binary_data = file.read()
        crl = x509.load_pem_x509_crl(binary_data)
        with urllib.request.urlopen('https://public.qcdigitalhub.com/certs/'+cn+'.pem') as file:
            # with urllib.request.urlopen('https://public.qcdigitalhub.com/CERTS/eCEV-SignerCert1-ECDSA.pem') as file:
            binary_cert = file.read()
        cert = x509.load_pem_x509_certificate(binary_cert)
        with urllib.request.urlopen('https://public.qcdigitalhub.com/certs/CAcert.pem') as file:
            binary_ca_cert = file.read()
        cacert = x509.load_pem_x509_certificate(binary_ca_cert)
        public_key = cacert.public_key()
        crlValidity = crl.is_signature_valid(public_key)
        print(crlValidity)
        if crl.get_revoked_certificate_by_serial_number(cert.serial_number) == None and crlValidity and cacert.not_valid_before <= datetime.now() <= cacert.not_valid_after:
            status = "NOTREVOKED"
        else:
            status = 'REVOKED'
        print(status)
        response = JsonResponse({'status': status})
        response.status_code = 200
        return response


@csrf_exempt
@api_view(['POST'])
@renderer_classes([JSONRenderer])
@permission_classes([IsAuthenticated])
def appose_cev(request):
    if request.method == 'POST':
        form = request.data
        # coordinates = json.loads(form.data['position'])
        image_name = generate_datamatrix(form['c40data'])
        response = JsonResponse({'file': image_name})
        response.status_code = 200
        return response

@csrf_exempt
@api_view(['POST'])
@renderer_classes([JSONRenderer])
def generate_cev(request):
    if request.method == 'POST':
        form = request.data
        image_name = generate_datamatrix(form['data'])
        encoded = encode(form['data'].encode('utf8'), scheme='C40')
        img = Image.frombytes(
            'RGB', (encoded.width, encoded.height), encoded.pixels)
        imageComp = img
        current_time = time.time()
        random_number = random.randint(1, 1000000)
        base_dir = os.path.join(BASE_DIR, 'CEVs')
        image_name = str(current_time) + '-' + str(random_number)+'.png'
        image_path = os.path.join(base_dir, image_name)
        imageComp.save(image_path)

        with open(image_path, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
        response = JsonResponse({'cev': encoded_string})
        response.status_code = 200
        return response


@csrf_exempt
@api_view(['POST'])
@renderer_classes([JSONRenderer])
def verify_data(request):
    data = request.data['data']
    type = str(request.data['type']).lower()
    errors = validate(type, data)
    schema = check_schema(type)
    if len(errors) > 0 and schema == False:
        response = JsonResponse({
            'status': 'invalid',
            'errors': errors
        })
        response.status_code = 200
        return response
    response = JsonResponse({
        'status': 'valid',
    })
    response.status_code = 200
    return response 

# def validate(type, data):
#     # pip install lxml
#     with urllib.request.urlopen('https://public.qcdigitalhub.com/manifests/manifeste-'+type+'.xml') as file:
#         manifest_data = file.read()
#     # Parse the manifest file
#     manifest = etree.fromstring(manifest_data)
#     # Validate the data against the schema
#     schema = manifest.find('.//Schema')
#     payload = schema.find('.//Payload')
#     fields = payload.find('.//Fields')
#     errors = []
#     for field in fields:
#         field_name = field.get('name')
#         field_type = field.tag
#         field_value = data.get(field_name)

#         if field_value is None:
#             if field.find('.//Nillable') is None:
#                 errors.append(f'{field_name} is required')
#         else:
#             if field_type == 'String':
#                 string_constraints = field.find('.//StringConstraints')
#                 if string_constraints is not None:
#                     if string_constraints.find('.//MaxLength') is not None:
#                         max_length = int(string_constraints.find('.//MaxLength').text)
#                         if isinstance(field_value, str) and len(field_value) > max_length:
#                             errors.append(f'{field_name} must be at most {max_length} characters long')
#                         elif not isinstance(field_value, str):
#                             errors.append(f'{field_name} must be a string')
#                     if string_constraints.find('.//MinLength') is not None:
#                         min_length = int(string_constraints.find('.//MinLength').text)
#                         if isinstance(field_value, str) and len(field_value) < min_length:
#                             errors.append(f'{field_name} must be at least {min_length} characters long')
#                     if string_constraints.find('.//Pattern') is not None:
#                         pattern = string_constraints.find('.//Pattern').text
#                         if isinstance(field_value, str) and not bool(re.match(pattern, field_value)):
#                             errors.append(f'{field_name} does not match pattern constraint')
#             elif field_type == 'StringArray':
#                 array_constraints = field.find('.//ArrayConstraints')
#                 if array_constraints is not None:
#                     if array_constraints.find('.//MinSize') is not None:
#                         min_size = int(array_constraints.find('.//MinSize').text)
#                         if len(field_value) < min_size:
#                             errors.append(
#                                 f'{field_name} must have at least {min_size} elements')
#                     if array_constraints.find('.//MaxSize') is not None:
#                         max_size = int(array_constraints.find('.//MaxSize').text)
#                         if len(field_value) > max_size:
#                             errors.append(
#                                 f'{field_name} must have at most {max_size} elements')
#                     string_constraints = field.find('.//StringConstraints')
#                     if string_constraints is not None:
#                         if string_constraints.find('.//MaxLength') is not None:
#                             max_length = int(
#                                 string_constraints.find('.//MaxLength').text)
#                             for value in field_value:
#                                 if len(value) > max_length:
#                                     errors.append(
#                                         f'{field_name} elements must be at most {max_length} characters long')
#                                 if string_constraints.find('.//Pattern') is not None:
#                                     pattern = string_constraints.find(
#                                         './/Pattern').text
#                                     if not bool(re.match(pattern, value)):
#                                         errors.append(
#                                             f'{field_name} elements do not match pattern constraint')
#             elif field_type == 'Integer':
#                 integer_constraints = field.find('.//IntegerConstraints')
#                 if integer_constraints is not None:
#                     if integer_constraints.find('.//Min') is not None:
#                         min_value = int(integer_constraints.find('.//Min').text)
#                         if field_value < min_value:
#                             errors.append(f'{field_name} must be at least {min_value}')
#                     if integer_constraints.find('.//Max') is not None:
#                         max_value = int(integer_constraints.find('.//Max').text)
#                         if field_value > max_value:
#                             errors.append(f'{field_name} must be at most {max_value}')
#             elif field_type == 'Date':
#                 date_constraints = field.find('.//DateConstraints')
#                 if date_constraints is not None:
#                     if date_constraints.find('.//From') is not None:
#                         from_date = date.fromisoformat(
#                             date_constraints.find('.//From').text)
#                         field_date = date.fromisoformat(field_value)
#                         if field_date < from_date:
#                             errors.append(
#                                 f'{field_name} must be on or after {from_date.isoformat()}')
#             elif field_type == 'Object':
#                 object_constraints = field.find('.//ObjectConstraints')
#                 if object_constraints is not None:
#                     if object_constraints.find('.//Nillable') is None:
#                         errors.append(f'{field_name} is required')
#             elif field_type == 'ObjectArray':
#                 array_constraints = field.find('.//ArrayConstraints')
#                 if array_constraints is not None:
#                     if array_constraints.find('.//MinSize') is not None:
#                         min_size = int(array_constraints.find('.//MinSize').text)
#                         if len(field_value) < min_size:
#                             errors.append(
#                                 f'{field_name} must have at least {min_size} elements')
#                     if array_constraints.find('.//MaxSize') is not None:
#                         max_size = int(array_constraints.find('.//MaxSize').text)
#                         if len(field_value) > max_size:
#                             errors.append(
#                                 f'{field_name} must have at most {max_size} elements')
#                     object_constraints = field.find('.//ObjectConstraints')
#                     if object_constraints is not None:
#                         if object_constraints.find('.//Nillable') is None:
#                             errors.append(f'{field_name} elements are required')
#     return errors


def validate(type_name, data):
    # Récupérer le manifeste
    with urllib.request.urlopen(f'https://public.qcdigitalhub.com/manifests/manifeste-{type_name}.xml') as file:
        manifest_data = file.read()

    manifest = etree.fromstring(manifest_data)
    schema = manifest.find('.//Schema')
    payload = schema.find('.//Payload')
    fields = payload.find('.//Fields')

    errors = []

    def validate_field(field_element, field_value, parent_name=''):
        field_type = field_element.get('type') or field_element.tag
        field_name = field_element.get('name')
        full_name = f"{parent_name}.{field_name}" if parent_name else field_name

        # Vérifier si le champ est obligatoire
        nillable = field_element.find('.//Nillable') is not None
        if field_value is None:
            if not nillable:
                errors.append(f"{full_name} is required")
            return

        # String
        if field_type.lower() == 'string':
            string_constraints = field_element.find('.//StringConstraints')
            if string_constraints is not None:
                if string_constraints.find('.//MaxLength') is not None:
                    max_length = int(string_constraints.find('.//MaxLength').text)
                    if len(str(field_value)) > max_length:
                        errors.append(f"{full_name} must be at most {max_length} characters long")
                if string_constraints.find('.//MinLength') is not None:
                    min_length = int(string_constraints.find('.//MinLength').text)
                    if len(str(field_value)) < min_length:
                        errors.append(f"{full_name} must be at least {min_length} characters long")
                if string_constraints.find('.//Pattern') is not None:
                    pattern = string_constraints.find('.//Pattern').text
                    if not re.match(pattern, str(field_value)):
                        errors.append(f"{full_name} does not match pattern constraint")

        # Integer
        elif field_type.lower() == 'integer':
            integer_constraints = field_element.find('.//IntegerConstraints')
            try:
                val = int(field_value)
                if integer_constraints is not None:
                    if integer_constraints.find('.//Min') is not None:
                        min_val = int(integer_constraints.find('.//Min').text)
                        if val < min_val:
                            errors.append(f"{full_name} must be at least {min_val}")
                    if integer_constraints.find('.//Max') is not None:
                        max_val = int(integer_constraints.find('.//Max').text)
                        if val > max_val:
                            errors.append(f"{full_name} must be at most {max_val}")
            except:
                errors.append(f"{full_name} must be an integer")

        # Date
        elif field_type.lower() == 'date':
            date_constraints = field_element.find('.//DateConstraints')
            try:
                field_date = date.fromisoformat(field_value)
                if date_constraints is not None:
                    if date_constraints.find('.//From') is not None:
                        from_date = date.fromisoformat(date_constraints.find('.//From').text)
                        if field_date < from_date:
                            errors.append(f"{full_name} must be on or after {from_date.isoformat()}")
            except:
                errors.append(f"{full_name} must be a valid date (YYYY-MM-DD)")

        # Object
        elif field_type.lower() == 'object':
            type_ref = field_element.get('type')
            # trouver le type dans <Types>
            type_def = schema.find(f".//Type[@name='{type_ref}']")
            if type_def is not None:
                sub_fields = type_def.find('.//Fields')
                for sub_field in sub_fields:
                    sub_value = field_value.get(sub_field.get('name')) if isinstance(field_value, dict) else None
                    validate_field(sub_field, sub_value, full_name)

        # ObjectArray
        elif field_type.lower() == 'objectarray':
            type_ref = field_element.get('type')
            type_def = schema.find(f".//Type[@name='{type_ref}']")
            if isinstance(field_value, list) and type_def is not None:
                sub_fields = type_def.find('.//Fields')
                for idx, item in enumerate(field_value):
                    for sub_field in sub_fields:
                        sub_value = item.get(sub_field.get('name'))
                        validate_field(sub_field, sub_value, f"{full_name}[{idx}]")
            else:
                errors.append(f"{full_name} must be an array of objects")

        # StringArray
        elif field_type.lower() == 'stringarray':
            if isinstance(field_value, list):
                array_constraints = field_element.find('.//ArrayConstraints')
                if array_constraints is not None:
                    if array_constraints.find('.//MinSize') is not None:
                        min_size = int(array_constraints.find('.//MinSize').text)
                        if len(field_value) < min_size:
                            errors.append(f"{full_name} must have at least {min_size} elements")
                    if array_constraints.find('.//MaxSize') is not None:
                        max_size = int(array_constraints.find('.//MaxSize').text)
                        if len(field_value) > max_size:
                            errors.append(f"{full_name} must have at most {max_size} elements")
                string_constraints = field_element.find('.//StringConstraints')
                if string_constraints is not None:
                    for idx, val in enumerate(field_value):
                        validate_field(field_element, val, f"{full_name}[{idx}]")
            else:
                errors.append(f"{full_name} must be an array of strings")

    # Valider tous les champs du payload
    for field in fields:
        value = data.get(field.get('name')) if isinstance(data, dict) else None
        validate_field(field, value)

    return errors

def check_schema(type):
    with urllib.request.urlopen('https://public.qcdigitalhub.com/manifests/manifeste-'+type+'.xml') as file:
        xml_data = file.read()

    with urllib.request.urlopen('https://public.qcdigitalhub.com/xsds/manifeste-'+type+'.xsd') as file:
        xsd_data = file.read()

    # Parse the XSD file
    xsd = etree.fromstring(xsd_data)

    # Create a schema object from the XSD file
    schema = etree.XMLSchema(xsd)

    # Parse the XML file
    xml = etree.fromstring(xml_data)

    # Validate the XML file against the schema
    try:
        schema.assertValid(xml)
        return True
    except etree.DocumentInvalid as e:
        return False

def generate_datamatrix(data):
    encoded = encode(data.encode('utf8'), scheme='C40')
    img = Image.frombytes(
        'RGB', (encoded.width, encoded.height), encoded.pixels)
    dim = img.size
    # .resize((int(dim[0]/3.), int(dim[1]/3.)))
    imageComp = img
    current_time = time.time()
    random_number = random.randint(1, 1000000)
    base_dir = os.path.join(BASE_DIR, 'CEVs')
    image_name = str(current_time) + '-' + str(random_number)+'.png'
    imageComp.save(os.path.join(base_dir, image_name))
    return os.path.join(base_dir, image_name)

def stream_http_download(request, file_path):
    print('in')
    try:
        base_dir = os.path.join(BASE_DIR, 'PDFs')
        pdf_name = file_path
        out_pdf_file = os.path.join(base_dir, pdf_name)
        response = StreamingHttpResponse(open(out_pdf_file, 'rb'))
        response['content_type'] = "application/octet-stream"
        response['Content-Disposition'] = 'attachment; filename=' + \
            os.path.basename(out_pdf_file)
        return response
    except Exception:
        raise Http404
    
def stream_cev_http_read(request, file_path):
    try:
        base_dir = os.path.join(BASE_DIR, 'CEVs')
        image_name = file_path
        out_cev_file = os.path.join(base_dir, image_name)
        with open(out_cev_file, 'rb') as f:
            image_data = f.read()
        return HttpResponse(image_data, content_type='image/png')
    except Exception:
        raise Http404

def stream_cev_http_download(request, file_path):
    try:
        base_dir = os.path.join(BASE_DIR, 'CEVs')
        image_name = file_path
        out_cev_file = os.path.join(base_dir, image_name)
        response = StreamingHttpResponse(open(out_cev_file, 'rb'))
        response['content_type'] = "application/octet-stream"
        response['Content-Disposition'] = 'attachment; filename=' + \
            os.path.basename(out_cev_file)
        return response
    except Exception:
        raise Http404


def upload(request):
    if request.FILES:
        form = UploadForm(request.POST, request.FILES)
    return form


@csrf_exempt
@api_view(['POST'])
@renderer_classes([JSONRenderer])
@permission_classes([IsAuthenticated])
def verifiysignature(request):
    data = request.data['message']
    splited = data.split('<US>')
    signature_b32 = splited[1]
    # signature = base64.b64decode('MEYCIQDtbfTeOAQj+OIlDw5HiIuSyxJXMo65pzyEdQ/zvoEGngIhAKlR8x8ypdCGCBMYz4YjhpQNC0AnbCinR/GnRl40HP7l')
    signature = base64.b64decode(signature_b32)
    # data_to_verify = 'DC04FR000001198519D31201FR90MAITRE/SPECIMEN/NATACHA<GS>92RAISON SOCIALE DE TEST<GS>94SAISIE CONSERVATOIREDE CREANCES<GS>9621112017<GS>91MME/BERTHIER/CORINNE<GS>93RAISON SOCIALE DU TIERS CONCERNE<GS>951896547853AB<GS>0CNB2WS43TNFSXELLKOVZXI2LDMUXGM4RPGE4DSNRVGQ3TQNJTIFBA<GS>'.encode()
    data_to_verify = splited[0].encode()
    with urllib.request.urlopen('https://public.qcdigitalhub.com/certs/'+request.data['certid']+'.pem') as file:
        binary_cert = file.read()
    cert = x509.load_pem_x509_certificate(binary_cert)
    public_key = cert.public_key()
    # print(cert.issuer)
    print(cert.subject.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME)[0].value)
    try:
        if (cert.not_valid_before <= datetime.now() <= cert.not_valid_after):
            public_key.verify(
                signature,
                data_to_verify,
                ec.ECDSA(hashes.SHA256()),
            )
            status = 'valid'
            print("La signature est valide.")
        else:
            status = 'invalid'
            print("La signature n'est pas valide.")
    except Exception as e:
        status = 'invalid'
        print("La signature n'est pas valide :", str(e))
    response = JsonResponse({
        'status': status,
        'cn': cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
        'o': cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value,
        'ou': cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value,
        'issuer': cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value+','+cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value,
        'from': cert.not_valid_before,
        'to': cert.not_valid_after
    })
    response.status_code = 200
    return response


def get_pub_key(cn):
    with urllib.request.urlopen('https://public.qcdigitalhub.com/certs/'+cn+'.pem') as file:
        binary_cert = file.read()
    cert = x509.load_pem_x509_certificate(binary_cert)
    public_key = cert.public_key()
    public_key.verify()
    return {
        'cert': cert,
        'public_key': public_key
    }
