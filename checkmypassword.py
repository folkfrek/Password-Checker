import requests
import hashlib
import sys 

def request_api_data(query_char):
	"""Request data from API using first 5 characters of hash password """
	url = 'https://api.pwnedpasswords.com/range/' + query_char
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')
	return res

def get_password_leaks_count(hashes, hash_to_check):
	"""return the amount for hash we are checking for password leaks""" 
	# split each line into the hash and amount of times breached
	hashes = (line.split(':') for line in hashes.text.splitlines())
	# iterate through hashes, hash matches hash we are checking return count
	for h, count in hashes:
		if h == hash_to_check:
			return count 
	return 0


def pwned_api_check(password):
	"""return the amount of times a given password was hacked. Checking password if it exist in API response """
	# create sha1 hash password
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	# split the first 5 chars of hash and the res
	first5_char, tail = sha1password[:5], sha1password[5:]
	# get all passwords that start with first 5 characters
	response = request_api_data(first5_char)
	# get number of leaks based on responses and tail
	number_leaks = get_password_leaks_count(response, tail)
	return number_leaks

def main(args):
	"""Check each password given"""
	# for each password given
	for password in args:
		# check if password has been hacked
		count = pwned_api_check(password)
		# if password has been hacked
		if count:
			print(f'{password} was found {count} times.. you should probably change your password')
		else:
			print(f'{password} was not found. Carry on!')
	return 'done'

if __name__ == '__main__':
	sys.exit(main(sys.argv[1:]))
