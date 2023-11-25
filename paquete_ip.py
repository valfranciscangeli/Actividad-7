# funcion auxiliar:
def rellenar_con_ceros(numero, digitos):
    numero_str = str(numero)
    largo_numero = len(numero_str)

    assert largo_numero <= digitos, "El numero excede el largo maximo"

    ceros_a_agregar = digitos - largo_numero

    numero_ajustado_str = '0' * ceros_a_agregar + numero_str

    return numero_ajustado_str


# clase para representar un paquete IP  ===============================================


class PaqueteIP:
    global separador
    separador = ";"

    def __init__(self, puerto="0", ttl="0", id="0", offset="0", tamanho="0", flag="1", mensaje=""):
        # valores por defecto para simular un constructor "vacio" para usar en fragmentacion
        self.ip: str = "127.0.0.1"  # siempre vamos a usar esta ip
        self._puerto: str = rellenar_con_ceros(puerto, 4)
        self._ttl: str = rellenar_con_ceros(ttl, 3)
        self._id: str = rellenar_con_ceros(id, 8)
        self._offset: str = rellenar_con_ceros(offset, 8)
        self._tamanho: str = rellenar_con_ceros(tamanho, 8)
        self._flag: str = rellenar_con_ceros(flag, 1)
        self.mensaje: str = mensaje

    # getter y setter para puerto
    @property
    def puerto(self):
        return int(self._puerto)

    @puerto.setter
    def puerto(self, value):
        self._puerto = rellenar_con_ceros(value, 4)

    # getter y setter para ttl
    @property
    def ttl(self):
        return int(self._ttl)

    @ttl.setter
    def ttl(self, value):
        self._ttl = rellenar_con_ceros(value, 3)

    # getter y setter para id
    @property
    def id(self):
        return int(self._id)

    @id.setter
    def id(self, value):
        self._id = rellenar_con_ceros(value, 8)

    # getter y setter para offset
    @property
    def offset(self):
        return int(self._offset)

    @offset.setter
    def offset(self, value):
        self._offset = rellenar_con_ceros(value, 8)

    # getter y setter para tamanho
    @property
    def tamanho(self):
        return int(self._tamanho)

    @tamanho.setter
    def tamanho(self, value):
        self._tamanho = rellenar_con_ceros(value, 8)

    # getter y setter para flag
    @property
    def flag(self):
        return int(self._flag)

    @flag.setter
    def flag(self, value):
        self._flag = rellenar_con_ceros(value, 1)

    def __str__(self):
        return f'{self.ip}{separador}{self._puerto}{separador}{self._ttl}{separador}{self._id}{separador}{self._offset}{separador}{self._tamanho}{separador}{self._flag}{separador}{self.mensaje}'

    def get_header(self):
        return f'{self.ip}{separador}{self._puerto}{separador}{self._ttl}{separador}{self._id}{separador}{self._offset}{separador}{self._tamanho}{separador}{self._flag}'

    def header_size(self):
        return len(self.get_header().encode())+1

    def __eq__(self, otro):
        if isinstance(otro, PaqueteIP):
            return (
                self.ip == otro.ip and
                self._puerto == otro._puerto and
                self._ttl == otro._ttl and
                self._id == otro._id and
                self._offset == otro._offset and
                self._tamanho == otro._tamanho and
                self._flag == otro._flag and
                self.mensaje == otro.mensaje
            )
        return False
