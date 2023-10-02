from django import template

register = template.Library()


def can_delete(obj, access_token):
    return obj.has_scope(access_token, 'delete')


register.filter('can_delete', can_delete)
