# clase de cola circular para poder implementar round robin

class CircularQueue:
    def __init__(self):
        self.queue = []
        self.__first = self.rear = -1

    def is_empty(self):
        return self.__first == -1

    def enqueue(self, elemento):
        if self.is_empty():
            self.__first = self.rear = 0
        else:
            self.rear = (self.rear + 1) % len(self.queue)

        self.queue.append(elemento)

    def dequeue(self):
        if self.is_empty():
            print("La cola está vacía. No se puede desencolar.")
            return None

        elemento = self.queue[self.__first]

        if self.__first == self.rear:
            self.__first = self.rear = -1
        else:
            self.__first = (self.__first + 1) % len(self.queue)

        return elemento

    def get_first(self):
        if self.is_empty():
            print("La cola está vacía.")
            return None

        first_value = self.queue[self.__first]
        self.__first = (self.__first + 1) % len(self.queue)

        return first_value

    def __str__(self) -> str:
        final = "\n tabla de rutas: \n"
        for valor in self.queue:
            final += str(valor) + "\n"
        return final

# test:

# cola = CircularQueue()

# cola.enqueue(1)
# cola.enqueue(2)
# cola.enqueue(3)

# print("primer valor en cola:", cola.get_first())
# print("primer valor en cola:", cola.get_first())
# print("primer valor en cola:", cola.get_first())
# print("primer valor en cola:", cola.get_first())
# print("primer valor en cola:", cola.get_first())
# print("primer valor en cola:", cola.get_first())
# print("primer valor en cola:", cola.get_first())
# print("primer valor en cola:", cola.get_first())
