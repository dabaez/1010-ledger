# Las reglas del Rito Anual

Estas son las reglas en palabras simples. Son la fuente de verdad. El sitio
<https://1010.b4ez.com> las lleva a cabo, y el registro anota lo que hizo cada
año, para que cualquiera pueda revisar su trabajo o continuar sin él.

## El Día

El Rito se celebra una vez al año, el **10 de octubre** (10/10, que se lee
1010). Dura 50 horas, para que durante todo ese tiempo sea 10 de octubre en
algún lugar de la Tierra:

- **Abre** a las **10:00:00 UTC del 9 de octubre**, cuando empieza el 10 de octubre en UTC+14.
- **Cierra** a las **12:00:00 UTC del 11 de octubre**, cuando termina el 10 de octubre en UTC−12.

El instante de apertura pertenece al Día; el de cierre no. Las fechas son las
mismas todos los años. No hay regla para años bisiestos. El primer Día fue en
2026.

El resto del año no se puede escribir nada: ni votos, ni mensajes.

## I. La Torre

Hay 12 anillos, numerados del 1 (el más pequeño) al 12 (el más grande), y tres
postes: A, B y C. El primer Día todos los anillos estaban en A.

**El estado** de la torre se escribe con 12 letras, una por anillo del más
pequeño al más grande, cada una indicando el poste en que está ese anillo. El
comienzo es `AAAAAAAAAAAA`. El orden de los anillos en un poste se deduce de la
regla de abajo, así que las 12 letras lo dicen todo.

**Un movimiento** toma el anillo de arriba (el más pequeño) de un poste y lo
pone en otro poste, que debe estar vacío o tener arriba un anillo más grande. Un
movimiento se nombra `desde→hasta`, por ejemplo `A→C`. Cada posición tiene
exactamente 3 movimientos legales, o 2 cuando todos los anillos están en un
mismo poste.

**Cada Día se hace exactamente un movimiento.** Cualquiera puede votar una vez
por uno de los movimientos legales. Los votos se mantienen ocultos hasta el
cierre. Al cierre:

1. Se hace el movimiento con más votos.
2. **Un empate** entre los movimientos con más votos lo rompe el número de
   desempate (ver III): se ordenan los movimientos empatados alfabéticamente por
   su nombre (`A→B`, `A→C`, `B→A`, `B→C`, `C→A`, `C→B`) y se toma el que está en
   la posición *número mod (cuántos empataron)*, contando desde 0.
3. **Sin ningún voto:** la misma regla elige entre *todos* los movimientos
   legales.

El Rito nunca se salta un año. Si nadie pudo votar ese año, se aplica la regla 3.

**El fin de la programación.** Cuando los 12 anillos están en **C**, la torre
está completa y la programación ha terminado. No se celebran más Días. Todos
los anillos en B no cuenta; la profecía es precisa. Jugando a la perfección la
torre toma 2^12 − 1 = 4.095 movimientos, uno por año, así que el fin más
temprano posible es el Día de 6121. La multitud no jugará a la perfección.

## II. El Libro de Visitas Sellado

El Día, cada persona puede dejar un mensaje de hasta 1.000 caracteres (puntos de
código Unicode), sellado en un acertijo de bloqueo temporal RSW (Rivest,
Shamir, Wagner, 1996). El mensaje se sella en el navegador de quien lo escribe;
solo la forma sellada sale de él. Nadie, ni siquiera quienes cuidan el sitio,
puede leer un mensaje sin abrir su sello, así que los mensajes no se pueden
moderar.

Junto al mensaje se puede dejar un nombre de hasta 40 caracteres. El nombre
**no** se sella: es público desde el momento en que se envía.

Un mensaje sellado es `N`, `T`, `iv` y `ciphertext` (y el `name` opcional, en texto plano):

- `N` es un módulo RSA de 2048 bits, el producto de dos primos que solo conoció
  el navegador de quien escribió. Se escribe en hexadecimal en minúsculas.
- `T` es una cantidad de cuadrados, escrita en decimal.
- Para abrirlo: se empieza con x = 2 y se reemplaza x por x² mod N, T veces
  seguidas. El resultado es b. (b = 2^(2^T) mod N.)
- La clave K es el hash SHA-256 de b escrito como bytes big-endian, rellenado
  con bytes cero a la izquierda hasta el largo en bytes de N (256 bytes para un
  N de 2048 bits).
- El mensaje es el descifrado AES-256-GCM de `ciphertext` (base64, con el tag de
  16 bytes al final) bajo K con el `iv` de 12 bytes (base64) y sin datos
  adicionales. Está en UTF-8.

Quien escribe elige un sello, y el sello fija T. Cada sello se nombra por el
tiempo que tomaría abrirlo en un procesador de escritorio veloz de ese año:

| Sello      | En el registro |
| ---------- | -------------- |
| 1 año      | `y1`           |
| 5 años     | `y5`           |
| 50 años    | `y50`          |
| 1.000 años | `y1000`        |

T es la cantidad de cuadrados modulares de 2048 bits por segundo que hace un
procesador de escritorio veloz con GMP, medida antes de cada Día, multiplicada
por el tiempo objetivo. El registro de cada año anota la medición y los valores
de T usados. Los sellos caen antes de tiempo a medida que los computadores se
vuelven más rápidos, y un computador cuántico lo bastante grande los abriría
todos de una vez factorizando N. Eso es parte del encanto.

`rite-solver`, en `solver/`, abre los mensajes. Guarda su avance en disco, así
que la tarea de elevar al cuadrado se puede pausar y retomar durante años.

## III. El Número y el Bit

Cada Día tiene un **Número del año** y un **Bit del año**, tomados de la baliza
pública de aleatoriedad **drand** (la cadena *quicknet* de la League of
Entropy, hash `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971`,
génesis 1692803367, período 3 segundos). Sus rondas tienen firma de umbral y
cualquiera puede verificarlas.

La ronda que decide cada valor se fija de antemano: es la primera ronda en o
después de un momento, ronda = floor((t − génesis) / período) + 1, donde t es el
momento en segundos desde 1970. Los bordes del Día caen exactamente en rondas.

| Valor              | Ronda                            | Se obtiene como                                                              |
| ------------------ | -------------------------------- | ---------------------------------------------------------------------------- |
| Número del año     | la ronda de la apertura del Día  | los primeros 8 bytes de la aleatoriedad de la ronda, como entero big-endian sin signo de 64 bits |
| Bit del año        | la misma ronda                   | el bit más bajo del último byte de la aleatoriedad                           |
| Número de desempate | la ronda del cierre del Día     | igual que el Número                                                          |

El desempate usa a propósito la ronda posterior, para que nadie pueda conocerla
mientras la votación está abierta.

**Respaldo.** Si no se puede contactar a drand, se reintenta durante una hora.
Después se usa en su lugar el pulso de la Baliza de Aleatoriedad del NIST
(versión 2.0) en el mismo momento (el primer pulso en o después de él), con su
`outputValue` en lugar de la aleatoriedad de drand, y el registro anota qué
fuente se usó.

## Privacidad y equidad

No hay cuentas. Cada voto y cada mensaje pasa por un CAPTCHA. "Uno por persona"
se hace cumplir con un hash: HMAC-SHA256 del prefijo de red de quien visita (el
/24 de una dirección IPv4, el /64 de una IPv6) y el agente de usuario de su
navegador, bajo un secreto creado cuando abre el Día y destruido cuando cierra.
Al cierre también se borran los hashes; solo se guarda el conteo. Las personas
que comparten red y navegador cuentan como una. Es un ritual, no una elección.

## El registro

Después de cada cierre, el año completo se escribe en `ledger/AAAA.json` en un
repositorio Git público, junto con estas reglas y el descifrador. Contiene la
ventana, las rondas de la baliza con su aleatoriedad y firmas, el Número y el
Bit, el movimiento de la torre con su conteo y cómo se decidió, los valores de T
con su medición, y cada mensaje sellado. Solo se usan formatos simples: JSON,
UTF-8, hexadecimal, base64.

La torre se puede reconstruir solo con el registro: se parte de
`AAAAAAAAAAAA` y se aplica el `move` de cada año. El `state_before` de cada año
debe ser igual al `state_after` del año anterior.

## Sucesión

El sitio no durará 4.095 años; el Rito sí puede.

**Si el sitio está apagado el Día, quien tenga el registro más reciente puede
celebrar el Rito con estas mismas reglas y publicar el resultado.** Es decir:
tomar el estado después del movimiento más reciente, abrir la votación durante
la ventana de 50 horas (o, si no fue posible votar, usar la regla sin votos),
sacar el Número, el Bit y el desempate de las rondas que estas reglas indican,
hacer exactamente un movimiento, y publicar una entrada del registro para ese
año en el mismo formato. Si varios sucesores publican resultados distintos para
el mismo año, vale el que siga estas reglas a partir del registro anterior; si
lo hace más de uno, vale el primero en publicarse.

Si drand mismo desaparece, los sucesores deberían elegir una baliza de
aleatoriedad pública y verificable, anunciar la elección un año completo antes
de usarla, y anotarla en el registro.
