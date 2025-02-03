import requests
from bs4 import BeautifulSoup
import sys
from urllib.parse import urljoin

s = requests.Session()
s.headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"

def get_forms(url): # Takes the url as an input and then fetches the webpage content
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    return soup.find_all("form")

def form_details(form): #Extractions info about each form (forms action, HTTP method and details about input field)
    detailsOfForm = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []
    
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type,
            "name" : input_name,
            "value" : input_value,
        })
        
    detailsOfForm['action'] = action
    detailsOfForm['method'] = method
    detailsOfForm['inputs'] = inputs
    return detailsOfForm
    
def if_contains(response): # Checks if there are common SQL common errors in the server response
    errors = {"string not terminated properly", #SQL Error patterns
              "uncloses quatation mark after the string", 
              "error in the SQL syntax marked"
              }
    for error in errors: 
        if error in response.content.decode().lower():
            return True
    return False

def injection_scan(url): # Finds all the forms on the given webapge
    forms = get_forms(url)
    print(f" [+] Detected {len(forms)} forms on {url}")
    
    for form in forms: 
        details = form_details(form)
        
        for i in "\"'":
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + i
                elif input_tag["type"] != 'submit':
                    data[input_tag['name']] = f"test{i}"
                    
                    
            print(url)
            form_details(form)
            
            if details["method"] == "post":
                res = s.post(url, data=data)
            elif details["method"] == "get":
                res = s.get(url, params = data)
            if if_contains(res):
                print("A SQL Injection attack is vulnerable in the link: ", url)
            else:
                print("No SQL Injection attack detected")
                break
            
if __name__ == "__main__":
    urlToBeChecked = "https://cnn.com"
    injection_scan(urlToBeChecked)