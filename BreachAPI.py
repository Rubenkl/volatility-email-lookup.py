'''
    Author: Ruben Kluge

'''

import requests
from ratelimit import limits, sleep_and_retry

# Suppress insecure platform warnings caused by
# the old python version of Volatility.
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()


apiUrl = "https://haveibeenpwned.com/api/v2/"
apiFunc = "breachedaccount"
params = {"User-Agent": "Email Checker for Volatility"}

class BreachAPI(object):
    def __init__(self):
        pass

    # Sort function to sort the dates. Sort by year, month and finally day
    def dateSort(self, apiObject):
        splits = apiObject['BreachDate'].split('-')
        return splits[0], splits[1], splits[2]


    @sleep_and_retry
    @limits(calls=1, period=2)
    def lookupBreachAPI(self, email):
        '''
        Grabs the email and looks it up in the HaveIBeenPwned dataset.

        Parameters:
            email: e-mail to be looked up.
        Returns: 
            email, breachdate, amount of breaches
        '''

        r = requests.get(apiUrl + apiFunc + "/" + email, params, verify=False)

        # API should not return anything else other than hit (200) or miss (404)
        if r.status_code not in [200, 404]:
            raise Exception('API response: {}'.format(r.status_code))

        # If there does not exist a record
        if r.status_code == 404:
            print(str(email) + " - " + "Does not exists" + " - " + "0")
        else:
            # Put all elements in an array
            breaches = []
            for el in r.json():
                breaches.append(el)
            breaches = sorted(breaches, key=self.dateSort)
            #print( str(email) + " - " + str(breaches[0]['BreachDate']) + " - " + str(len(breaches)) )
            return str(email), str(breaches[0]['BreachDate']), str(len(breaches))

        return False # An error occured


    # ------------------------

    '''
    maillist = ["test@hotmail.com", "test@example.com", "random@email.com"]
    print("EMAIL - First seen - breaches")
    for m in maillist:
        lookupBreachAPI(m)
    '''
