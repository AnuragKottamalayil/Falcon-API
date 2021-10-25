import json
# import falcon

# def test_demo(client):
#     response = client.simulate_get('/sample')
#     assert response.status == falcon.HTTP_200


import falcon
from falcon import testing
import pytest
from falcon_project.app import app


@pytest.fixture
def client():
    return testing.TestClient(app)


def test_register(client):

    headers = {
        'Content-Type': 'application/json',
    }
    
    data = {"name":"anurag", "email":"and@gmail.com", "mobile":89887768, "username":"anuragk", "password":"Anu0#$^^018"}
    url = '/Register'
    response = client.simulate_post(url, body=json.dumps(data), headers=headers)
 
    assert response.status == falcon.HTTP_200
    

def test_login(client):

    headers = {
        'Content-Type': 'application/json',
    }
    
    data = {"username":"anuragk", "password":"Anu0#$^^018"}
    url = '/Login'
    response = client.simulate_post(url, body=json.dumps(data), headers=headers)
 
    assert response.status == falcon.HTTP_200