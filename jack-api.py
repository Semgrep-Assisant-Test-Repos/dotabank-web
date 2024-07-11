from rest_framework.decorators import api_view


@api_view(["GET", "POST"])
def snippet_list(request):
    tainted = request.GET["query"]

    # ruleid: tainted-code-stdlib-django
    eval(tainted)
    # ruleid: tainted-code-stdlib-django
    exec(tainted)

    # ok: tainted-code-stdlib-django
    ast.literal_eval(tainted)

    # ok: tainted-code-stdlib-django
    eval("clean")
    # ok: tainted-code-stdlib-django
    exec("clean")

    # ok: tainted-code-stdlib-django
    ast.literal_eval("clean")
