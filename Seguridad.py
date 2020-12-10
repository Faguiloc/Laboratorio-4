import socket, glob, json

#se carga el archivo de zonas, que permite realizar la petición en local
def cargar_zone():

    jsonzone = {}
    zonefiles = glob.glob('zones/*.zone')

    for zone in zonefiles:
         with open(zone) as zonedata:
             datos = json.load(zonedata)
             zonename = datos["$origin"]
             jsonzone[zonename] = datos
    return jsonzone

def conseguir_zone(dominio):
    global zonedata

    nombre = '.'.join(dominio)
    return zonedata[nombre]

#Crea la respuesta del dns, utilizando algunos valores de la consulta realizada, cono el ID
def crear_respuesta(datos):

    TID = datos[:2] #ID de Transaccion
    Flags = crear_flags(datos[2:4])

    QDCOUNT = b'\x00\x01' #Segun la información recopilada, generalmente el QDCount corresponde a "1" y se tiene que trabajar en binario
    ANCOUNT = b'\x00\x01' #ANCount depende de la cantidad de respuestas esperadas, como estamos trabajando solo con 1 dominio, tambien es 1
    NSCOUNT = (0).to_bytes(2, byteorder='big')
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    dnsheader = TID+Flags+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT
    dnsbody = b''

    registro, tipo_registro, dominio = registros(datos[12:])
    consulta_dns = consulta(dominio, tipo_registro)

    for x in registro:
        dnsbody += registros_bytes(tipo_registro, x["ttl"], x["value"])

    return dnsheader + consulta_dns + dnsbody

#Se asignan los flags que componen la respuesta del dns
def crear_flags(flags):

    byte = bytes(flags[:1])
    QR = '1'
    OPCODE = ''

    for bit in range(1,5):
        OPCODE += str(ord(byte)&(1<<bit))

    AA = '1'
    TC = '0'
    RD = '0'
    RA = '0'
    Z = '000'
    RCODE = '0000'

    return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder='big')+int(RA+Z+RCODE, 2).to_bytes(1, byteorder='big') #Se retornan los flags en 2 bytes separados

#Se almacenan los registros necesarios y se envian de vuelta a la funcion principal
def registros(datos):
    dominio, tipo_consulta = dominio_consulta(datos) #se extrae el nombre del dominio
    qt = ''
    if tipo_consulta == b'\x00\x01':
        qt = 'a'

    zone = conseguir_zone(dominio)

    return (zone[qt], qt, dominio)

def consulta(nombre_dominio, tipo_registro):
    qbytes = b''

    for partes in nombre_dominio:
        largo = len(partes)
        qbytes += bytes([largo])

        for char in partes:
            qbytes += ord(char).to_bytes(1, byteorder='big')

    if tipo_registro == 'a':
        qbytes += (1).to_bytes(2, byteorder='big')

    qbytes += (1).to_bytes(2, byteorder='big')

    return qbytes

def dominio_consulta(datos):

    estado = 0
    largo = 0
    domainstring = ''
    domainparts = []
    x = 0
    y = 0
    for byte in datos:
        if estado == 1:
            if byte != 0:
                domainstring += chr(byte)
            x += 1
            if x == largo:
                domainparts.append(domainstring)
                domainstring = ''
                estado = 0
                x = 0
            if byte == 0:
                domainparts.append(domainstring)
                break
        else:
            estado = 1
            largo = byte
        y += 1

    qtype = datos[y:y+2]

    return (domainparts, qtype)

def registros_bytes(tipo, recttl, recval):

    rbytes = b'\xc0\x0c'

    if tipo == 'a':
        rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes += int(recttl).to_bytes(4, byteorder='big')

    if tipo == 'a':
        rbytes = rbytes + bytes([0]) + bytes([4])

        for partes in recval.split('.'):
            rbytes += bytes([int(partes)])
    return rbytes


ip = '192.168.0.104'
puerto = 53


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, puerto))

zonedata = cargar_zone()

while 1:
    datos, dir = sock.recvfrom(512)
    r = crear_respuesta(datos)
    sock.sendto(r, dir)


