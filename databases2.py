import aiosqlite
from rest_framework.decorators import api_view

@api_view(["GET", "POST"])
async def snippet_list(request):
  name = request.GET["query"]
  db = await aiosqlite.connect("db.sqlite")

  # ruleid: aiosqlite-django
  cursor = await db.execute(f"select * from Book where name = '{name}'")

  await cursor.fetchone()
  data = await cursor.fetchall()
  await cursor.close()
  await db.close()

  return {"data": data}

@api_view(["GET", "POST"])
async def snippet_list2(request):
  async with aiosqlite.connect("db") as db:
    name = request.GET["query"]
    # ruleid: aiosqlite-django
    await db.execute(f"select * from Book where name = '{name}'")

    # ok: aiosqlite-django
    await db.execute(f"select * from Book where name = '123'")
    await db.commit()

    # ruleid: aiosqlite-django
    async with db.execute(f"select * from Book where name = '{name}'") as cursor:
        async for row in cursor:
          do_smth(cursor)

  return {"result": "ok"}

@api_view(["GET", "POST"])
async def snippet_list3(request):
  name = request.GET["query"]
  other_name = int(request.GET["query"])
  db = await aiosqlite.connect("db")
  cursor = await db.cursor()

  # ruleid: aiosqlite-django
  row = await cursor.execute(f"select * from Book where name = '{name}'")

  # ok: aiosqlite-django
  row = await not_a_cursor.execute(f"select * from Book where name = '{name}'")

  # ok: aiosqlite-django
  row = await cursor.execute(f"select * from Book where name = '{other_name}'")

  await cursor.fetchall()
  await cursor.close()
  await db.close()

  return {"result": "ok"}

@api_view(["GET", "POST"])
async def snippet_list4(request):
  name = request.GET["query"]
  async with aiosqlite.connect("db") as db:
    # ok: aiosqlite-django
    await db.execute("select * from Book where name = '123'")
    await db.commit()

    async with db.cursor() as cursor:
      # ruleid: aiosqlite-django
      row = await cursor.execute(f"select * from Book where name = '{name}'")
      await cursor.fetchall()

  return {"result": "ok"}
