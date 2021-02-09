## API Server test calls in CURL

### GET
```bash
curl -v "http://localhost:3333/setup/gettrips?uuid=c2f5b91e-62a9-4a2c-9ce3-7ac5691510b5"
```

### POST
```bash
curl -v --request POST -H "Content-Type: application/json" --data '{"admin_id":"c2f5b91e-62a9-4a2c-9ce3-7ac5691510b5","name":"TestMalta"}' "http://localhost:3333/create/group"
```

### PUT
```bash
curl -v --request PUT -H "Content-Type: application/json" --data '{"groupid":"730f8990-d18e-4a55-a762-273eb3834867","numbers":["07971452162", "0181263"]}' "http://localhost:3333/create/addtogroup"
```

### PATCH
```bash
curl -v --request PATCH -H "Content-Type: application/json" --data '{"users":[{"uuid":"1234","key":"1234GroupKey"}]}' "http://localhost:3333/groups/83487ac4-28e9-4056-a101-75a124265601/users?id=Khwlfr1SiKcH3UOMlDgnMCsVFV63"
```
