from xml.dom import minidom
import shlex, subprocess, csv


class ReportHost():
	ip = ""
	mac = ""
	ports = []

class port():
	id = ""
	name = ""
	protocol = ""
	state = ""
	reason = ""
	reason_ttl = ""
	url = ""
	extraInfo = ""



doc = minidom.parse('C:\\Users\\FMAG\\allPorts.xml') #Lee el primer escaneo

#Lineas de report
report = []

#3
#Función que ejecuta el segundo escaneo por equipo pasando como parámetro la ip y los puertos abiertos
#Devuelve el resultado en xml
def runSecondNMAP(ip, ports):
	command_line1 = 'nmap -sC -sV -p'
	command_line2 = ports + " " + ip
	command = command_line1 + command_line2
	
	args = shlex.split(command)
	subprocess.call(args)
	insertLine(ip)
	
#2
#Procesamos el XML obtenido para cada uno de los equipos y lo guardamos como una línea en el report.
#Esta parte de la ejecución lo que hace es recorer el fichero XML creado para cada uno de los Equipos detectados.
def insertLine(ipAddress):
	xml_puertos = minidom.parse(ipAddress + '_ports')
	line = ReportHost()
	host = xml_puertos.getElementsByTagName("host")
	for h in host:
		IPS = h.getElementsByTagName("address")
		for IP in IPS:
			if IP.getAttribute("addrtype") == "ipv4":
				line.ip = IP.getAttribute("addr")
				line.puertos = h.getElementsByTagName("port")
				for p in line.puertos:
					p1 = port()
					port.id = p.getAttribute("portid")
					port.name= p.getAttribute("name")
					port.protocol = p.getAttribute("protocol")
					port.state =p.getAttribute("state")
					line.ports.append(p1)

			elif IP.getAttribute("addrtype") == "mac":
				line.mac = address.getAttribute("addr")
				

	report.append(line)
	
dispositivos= doc.getElementsByTagName("host")

contador = 0

#1
#Ejecuta por cada uno de los dispositivos de la lista un escaneo más profundo y guarda el resultado con formato XML en una lista.
for dispositivo in dispositivos:
	
	contador = contador + 1 #Número de equipo descubierto
	addresses = dispositivo.getElementsByTagName("address") #Direcciones del host
	print("Dispositivo encontrado: " + str(contador))
	#Recorre cada uno de los equipos encontrados, generando una nueva consulta a nmap para cada uno de ellos.
	for address in addresses:
		#Si la dirección es una dirección IPv4 se muestra como tal
		if address.getAttribute("addrtype") == "ipv4":
			print("Address:%s " % address.getAttribute("addr"))
			direccionIP = address.getAttribute("addr")

		#Si la dirección es una dirección MAC se muestra como tal
		elif address.getAttribute("addrtype") == "mac":
			print("Mac:%s " % address.getAttribute("addr"))

			#Aqui vamos mostrar todos los puertos que se han encontrado abiertos.
			puertos = dispositivo.getElementsByTagName("port")
			puertos_array = ['0'] #Puertos en string para que ejecutar la segunda parte del escaneo

			#Recorre cada uno de los puertos detectado para elaborar la segunda consulta a nmap
			for puerto in puertos:
				numeroPuerto = puerto.getAttribute("portid")
				puertos_array.append(numeroPuerto)

			#Llama a la función para ejecutar el anális más en profundidad. Lo muestra por pantalla.
			#y guarda un fichero XML con el resultado.
			runSecondNMAP(direccionIP, ",".join(puertos_array) + " -oX " + direccionIP + "_ports")


#4
#Una vez obtenida toda la información generamos un CSV formateado para informe.
def generarReport():
	with open('reportEscaneoNMAP.csv', 'w', newline='') as csv_file:
		for host in report:
			writer = csv.writer(csv_file)
			writer.writerow(["IP", "MAC"])
			writer.writerow([host.ip, host.mac])
			writer.writerow(["Ports"])
			writer.writerow(["ID", "Name", "Protocol", "State"])
			for port in host.ports:
				writer.writerow([port.id, port.name, port.protocol])

generarReport()
