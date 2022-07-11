Start by installing required dependencies by running `pip install -r requirements.txt` (in a separate environment of course).

Then simply `uvicorn main:app --reload --port <port>` and you'll have this API up and running, go into http://127.0.0.1:\<port\>,
this is the root endpoint and will provide all the required instructions on how to use the API.
