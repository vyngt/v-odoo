import logging
import threading

import odoo
from odoo import http
from odoo.http import request
from odoo.service.model import execute, execute_kw


def dispatch(db, uid, method, params):
    threading.current_thread().dbname = db  # type: ignore
    threading.current_thread().uid = uid  # type: ignore
    registry = odoo.registry(db).check_signaling()
    with registry.manage_changes():
        if method == "execute":
            res = execute(db, uid, *params)
        elif method == "execute_kw":
            res = execute_kw(db, uid, *params)
        else:
            raise NameError("Method not available %s" % method)
    return res


class OAuthRPC(http.Controller):
    @http.route("/oauth2/rpc", type="json", auth="jwt", methods=["POST"])
    def jsonrpc(self, db: str, method: str, args):
        """
        ## Example
        ```js
        {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {
                "db": "<db_name>",
                "method": "execute",
                "args": [
                    "res.partner",
                    "search_read",
                    [],
                    ["name", "phone"],
                    0,
                    3
                ]
            },
            "id": 1234556
        }
        ```
        """
        return dispatch(db, request.env.user.id, method, args)
