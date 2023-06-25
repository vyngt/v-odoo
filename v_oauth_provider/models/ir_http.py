from odoo import api, fields, models
from odoo.http import request

# class IrHttpJWT(models.AbstractModel):
#     _inherit = "ir.http"

#     @classmethod
#     def _auth_method_oauth(cls):
#         api_key = request.httprequest.headers.get("Authorization")
#         # if not api_key:
#         #     raise BadRequest("Authorization header with API key missing")

#         # user_id = request.env["res.users.apikeys"]._check_credentials(
#         #     scope="rpc", key=api_key
#         # )
#         # if not user_id:
#         #     raise BadRequest("API key invalid")

#         request.uid = user_id
