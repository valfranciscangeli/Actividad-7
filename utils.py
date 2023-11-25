from cola_circular import *
import re
from paquete_ip import *
import random

# variables globales:
cola_de_rutas = CircularQueue()  # al inicio es vacía
debug = False

# funciones varias  ===============================================


def eliminar_duplicados_paquetes(lista_paquetes):
    lista_sin_duplicados = []
    for paquete in lista_paquetes:
        if paquete not in lista_sin_duplicados:
            lista_sin_duplicados.append(paquete)
    return lista_sin_duplicados


def dividir_string_en_bytes(string, m):
    # Convertir el string a bytes usando la codificación especificada
    bytes_string = string.encode()

    # Lista para almacenar los bloques resultantes
    fragmentos = []

    # Iterar sobre los bytes con pasos de tamaño m
    for i in range(0, len(bytes_string), m):
        # Agregar el bloque actual a la lista
        fragmentos.append(bytes_string[i:i + m])

    return fragmentos


# funciones de parsing  ===============================================


def create_packet(paquete_ip: PaqueteIP):
    return str(paquete_ip)


def parse_packet(IP_packet: str) -> PaqueteIP:
    # paquete debe venir codificado
    separador = ";"
    IP_packet = IP_packet.decode()
    IP_packet = IP_packet.rstrip("\n")
    recibido = IP_packet.split(separador)
    # se asume que todo lo que está desde el 7mo elemento es mensaje, por si este contiene al separador
    mensaje = (separador + '').join(recibido[7:])
    # mensaje = re.sub(r'\s+', ' ', mensaje)
    return PaqueteIP(recibido[1], recibido[2], recibido[3], recibido[4], recibido[5], recibido[6], mensaje)


# tests:
IP_packet_v1 = "127.0.0.1;8881;004;00000007;00000301;00000300;0;hola!, chao :c".encode()
parsed_IP_packet = parse_packet(IP_packet_v1)
IP_packet_v2_str = create_packet(parsed_IP_packet)
IP_packet_v2 = IP_packet_v2_str.encode()
assert IP_packet_v1 == IP_packet_v2
if debug:
    print("IP_packet_v1 == IP_packet_v2 ? {}".format(
        IP_packet_v1 == IP_packet_v2))


# funciones para trabajar los txt ===============================================


def leer_archivo(nombre_archivo):
    try:
        with open(nombre_archivo, 'r') as archivo:
            lineas = archivo.readlines()
            cola_resultado = CircularQueue()
            for linea in lineas:
                linea = linea.strip().split()
                n_valores = len(linea)
                diccionario = {
                    "red": linea[0],
                    "ruta_ASN": [linea[1:n_valores-3]],
                    "ip_siguiente_salto": linea[-3],
                    "puerto_siguiente_salto": int(linea[-2]),
                    "MTU": linea[-1]
                }
                cola_resultado.enqueue(diccionario)

            return cola_resultado

    except FileNotFoundError:
        if debug:
            print(f"El archivo {nombre_archivo} no se encuentra.")
        return None


# test
if debug:
    nombre_del_archivo = 'Conf_5_routers/rutas_R2_v3_mtu.txt'
    resultado = leer_archivo(nombre_del_archivo)

    if resultado and debug:
        print(resultado)


# manejo de rutas ==============================================

def check_routes(routes_file_name, destination_address):
    global cola_de_rutas
    if cola_de_rutas.is_empty():
        cola_de_rutas = leer_archivo(routes_file_name)
    dest_ip = destination_address[0]
    dest_port = destination_address[1]

    # buscamos la ruta en la lista
    total_rutas = len(cola_de_rutas.queue)
    contador = 0
    while contador < total_rutas:
        primera = cola_de_rutas.get_first()
        red = primera["red"]
        pto_ini = primera["ruta_ASN"][1]
        pto_fin = primera["ruta_ASN"][-1]
        if dest_ip == red and pto_ini <= dest_port <= pto_fin:
            # encontramos la ruta buscada
            return primera["ip_siguiente_salto"], primera["puerto_siguiente_salto"], primera["MTU"]

        contador += 1

    # no se encontró una ruta
    return None


# test:
if debug:
    archivo = "Conf_5_routers/rutas_R2_v3_mtu.txt"
    assert check_routes(archivo,                         ("127.0.0.1", 8884)) == (
        ('127.0.0.1', 8883), "50")
    assert check_routes(archivo,
                        ("127.0.0.1", 8880)) == None
    assert check_routes(archivo,
                        ("127.0.0.1", 8887)) == None


# funciones de fragmentacion =====================================================

def fragment_IP_packet(IP_packet: str, MTU: int):
    # IP_packet va a venir codificado
    fragmentos = []
    # tamaño de todo el paquete, con headers, en bytes
    tamanho_paquete = len(IP_packet)

    if tamanho_paquete <= MTU:
        fragmentos = [IP_packet.decode()]
    else:
        # excedemos el tamanho del enlace, toca fragmentar
        # valores comunes
        parsed_packet = parse_packet(IP_packet)
        puerto = parsed_packet.puerto
        ttl = parsed_packet.ttl
        id = parsed_packet.id
        flag_original = parsed_packet.flag

        offset = parsed_packet.offset

        fragment_header_len = parsed_packet.header_size()
        assert fragment_header_len == 48, "tamaño de header malo"
        tamanho_max_mensaje = MTU-fragment_header_len
        mensaje_pedazos = dividir_string_en_bytes(
            parsed_packet.mensaje, tamanho_max_mensaje)

        for i in range(len(mensaje_pedazos)):
            pedazo = mensaje_pedazos[i]
            if debug:
                print("pedazo:", pedazo.decode())
                print("offset:", offset)
            tamanho = len(pedazo)
            flag = 1
            if flag_original == 0 and i == len(mensaje_pedazos)-1:
                flag = 0
            nuevo_paquete = PaqueteIP(puerto, ttl, id, offset, tamanho, flag)
            nuevo_paquete.mensaje = pedazo.decode()

            fragmentos.append(create_packet(nuevo_paquete))

            # ahora, el offset debe crecer
            offset += nuevo_paquete.tamanho
    if debug:
        print("fragmentos:", fragmentos)
    return fragmentos


# tests:
paquete = "127.0.0.1;8885;010;00000347;00000000;00000005;0;hola!".encode()
test_mtu = 51
assert fragment_IP_packet(paquete, test_mtu) == [
    "127.0.0.1;8885;010;00000347;00000000;00000003;1;hol", "127.0.0.1;8885;010;00000347;00000003;00000002;0;a!"]

otro_paquete = "127.0.0.1;8885;010;00000347;00000000;00000005;1;hola!".encode()
otro_test_mtu = 50
assert fragment_IP_packet(otro_paquete, otro_test_mtu) == [
    "127.0.0.1;8885;010;00000347;00000000;00000002;1;ho", "127.0.0.1;8885;010;00000347;00000002;00000002;1;la", "127.0.0.1;8885;010;00000347;00000004;00000001;1;!"]


def reassemble_IP_packet(fragment_list):
    fragment_list = [parse_packet(fragmento.encode())
                     for fragmento in fragment_list]  # pasamos todos los paquetes a objetos PaqueteIP
    fragment_list = sorted(fragment_list, key=lambda x: x.offset)  # ordenamos
    fragment_list = eliminar_duplicados_paquetes(
        fragment_list)  # eliminamos duplicados
    # podria ser un paquete no fragmentado o incompleto, revisamos:
    if len(fragment_list) == 1:
        paquete = fragment_list[0]
        if paquete.offset == 0 and paquete.flag == 0:  # es un paquete completo
            return create_packet(paquete)
    else:
        # seguimos revisando solo si nos llegó por lo menos el principio y el final
        if fragment_list[0].offset == 0 and fragment_list[-1].flag == 0:
            puerto = fragment_list[0].puerto
            ttl = fragment_list[0].ttl
            id = fragment_list[0].id
            offset = 0
            tamanho = 0
            mensaje = ""
            for fragmento in fragment_list:
                if fragmento.tamanho != len(fragmento.mensaje.encode()):
                    # si un fragmento dice tener un tamanho que no corresponde al largo del mensaje se descarta
                    if debug:
                        print("se ignoro un fragmento por tamano\n")
                    break
                offset += fragmento.offset-offset
                if offset != tamanho:  # con esto revisamos que no esten faltando pedazos intermedios
                    if debug:
                        print(
                            f"offset y tamanho no coinciden: \n  offset: {offset} - tamanho: {tamanho}\n")
                    return None
                mensaje += fragmento.mensaje
                tamanho = len(mensaje.encode())

            final_packet = PaqueteIP(puerto, ttl, id, 0, tamanho, 0, mensaje)

            return create_packet(final_packet)
        if debug:
            print("Todavía no se reciben todos los fragmentos del paquete...\n")

    return None


# test:
# lista = ['127.0.0.1;8885;010;00000347;00000000;00000002;1;ho',
#          '127.0.0.1;8885;010;00000347;00000002;00000002;1;la', '127.0.0.1;8885;010;00000347;00000005;00000001;0;!']
# assert reassemble_IP_packet(lista) == None
lista2 = ['127.0.0.1;8885;010;00000347;00000000;00000002;1;ho',
          '127.0.0.1;8885;010;00000347;00000002;00000002;1;la', '127.0.0.1;8885;010;00000347;00000004;00000001;0;!']

assert reassemble_IP_packet(
    lista2) == "127.0.0.1;8885;010;00000347;00000000;00000005;0;hola!"
lista3 = ['127.0.0.1;8885;010;00000347;00000005;00000001;0;!']
assert reassemble_IP_packet(lista3) == None
lista4 = ["127.0.0.1;8885;010;00000347;00000000;00000005;0;hola!"]
assert reassemble_IP_packet(
    lista4) == "127.0.0.1;8885;010;00000347;00000000;00000005;0;hola!"

paquete1 = "127.0.0.1;8885;010;00000111;00000000;00000078;0;hola!, este es mi primer intento de paquete, espero que llegue bien y completo"
fragmentos1 = ['127.0.0.1;8885;010;00000111;00000000;00000032;1;hola!, este es mi primer intento',
               '127.0.0.1;8885;010;00000111;00000032;00000032;1; de paquete, espero que llegue b',
               '127.0.0.1;8885;010;00000111;00000064;00000014;0;ien y completo']
assert reassemble_IP_packet(fragmentos1) == paquete1

paquete2 = "127.0.0.1;8885;010;00000222;00000000;00000096;0;hola!, este es el segundo intento de paquete, espero que tambien llegue bien y completo, saludos"
fragmentos2 = ['127.0.0.1;8885;010;00000222;00000000;00000032;1;hola!, este es el segundo intent',
               '127.0.0.1;8885;010;00000222;00000032;00000032;1;o de paquete, espero que tambien',
               '127.0.0.1;8885;010;00000222;00000064;00000032;0; llegue bien y completo, saludos']
assert reassemble_IP_packet(fragmentos2) == paquete2


# test en conjunto: -------------------
IP_packet_v1, MTU = "127.0.0.1;8885;010;00000347;00000000;00000005;0;hola!".encode(), 50
fragment_list = fragment_IP_packet(IP_packet_v1, MTU)
if debug:
    print("resultado:", fragment_list)
IP_packet_v2_str = reassemble_IP_packet(fragment_list)
if debug:
    print("resultado:", IP_packet_v2_str)
IP_packet_v2 = IP_packet_v2_str.encode()
assert IP_packet_v1 == IP_packet_v2
if debug:
    print("IP_packet_v1 = IP_packet_v2 ? {}".format(
        IP_packet_v1 == IP_packet_v2))


# funciones para BGP ==============================================================

def create_BGP_message(init: bool = True, puerto=8888, ttl=10,  id=random.randint(0, 99999999)):
    mensaje = "START_BGP"
    if not init:
        mensaje = ""
    paquete_IP = PaqueteIP(puerto, ttl, id, 0, len(
        mensaje.encode()), 0, mensaje)
    return create_packet(paquete_IP)


# test:
# mensaje de inicio
assert create_BGP_message(
    id=111) == "127.0.0.1;8888;010;00000111;00000000;00000009;0;START_BGP"
# mensaje con rutas
assert create_BGP_message(
    init=False, id=111) == "127.0.0.1;8888;010;00000111;00000000;00000000;0;"


def run_BGP(router):
    print("iniciando bpg ... \n")
    while True:
        break
