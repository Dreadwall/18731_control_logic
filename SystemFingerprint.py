
class SystemFingerprint:
	port_service_speed = {}
	#port->[service, speed]

	ip_address = ""
	os = ""

	def __init__(self, pss, ip, os):
		self.port_service_speed = pss
		self.ip_address = ip
		self.os = os

	def gen_fingerprint(port_service, ip, speed_placeholder, os):
		port_service_speed = {}

		for port, service in port_service.items():
			port_service_speed[port] = [service, speed_placeholder]

		return SystemFingerprint(port_service_speed, ip, os)


	def equal_in_tolerance(self, sf, tolerance):
		non_equality = 0

		other_port_service_speeds = sf.get_port_service_speed()
		my_port_service_speeds = self.get_port_service_speed()

		for port, service_speed in my_port_service_speeds.items():
			if(port in other_port_service_speeds.keys()):
				# both port entries exist. Check service information

				if(service_speed[0] != other_port_service_speeds[port][0]):
					# if not equal, we will get another not equal hit in second loop
					# so we only add half point per hit
					non_equality = non_equality + 0.5
			else:
				# Port is not in other group, add full point
				non_equality = non_equality + 1

		for port, service_speed in other_port_service_speeds.items():
			if(port in my_port_service_speeds.keys()):
				# both port entries exist. Check service information

				if(service_speed[0] != my_port_service_speeds[port][0]):
					# if not equal, we will get another not equal hit in second loop
					# so we only add half point per hit
					non_equality = non_equality + 0.5
			else:
				# Port is not in other group, add full point
				non_equality = non_equality + 1

		my_ip_parts = self.ip_address.split(".")
		other_ip_parts = sf.get_ip_address().split(".")

		if(my_ip_parts[0] == other_ip_parts[0] and my_ip_parts[1] == other_ip_parts[1] and
			my_ip_parts[2] == other_ip_parts[2]):
			pass
		else:
			# Not in same /24 subnet, potentially far apart
			# We weight this a little more as its indicative of network admin policies
			non_equality = non_equality + 3


		if(self.get_os() != sf.get_os()):
			# This is also weighted heavier as boxes running different OS's may be drastically different
			# from each other. Even a version difference shows that there's not homogeneus boxes
			# which is what this classifier assumes for good results.
			non_equality = non_equality + 3

		if(non_equality <= tolerance):
			return True
		else:
			return False

	def get_os(self):
		return self.os

	def get_ip_address(self):
		return self.ip_address

	def get_port_service_speed(self):
		return self.port_service_speed

	def set_speed(self, port, speed):
		service, _ = self.port_service_speed[port] 
		self.port_service_speed[port] = [service, speed]



