# README

## Description

[Nest](https://github.com/nestjs/nest) framework TypeScript starter repository.

## Project setup

```bash
$ pnpm install
```

## Compile and run the project

```bash
# development
$ pnpm run start:dev

# watch mode
$ pnpm run start:dev

# production mode
$ pnpm run start:prod
```

## Run tests

```bash
# unit tests
$ npm run test

# e2e tests
$ npm run test:e2e

# test coverage
$ npm run test:cov
```

## Logs

### Watch Logs with `jq`
```bash
cat logs/app.log | jq -r '"[\(.timestamp)] [\(.level | ascii_upcase)] [\(.context)] \(.message)"'
```

```bash
cat logs/app.log | jq 'select(.level == "error")'
```

### Watch Logs with `pipe`
#### Prepare
##### Install:
```bash
npm install -g pino-pretty
```

#### using
##### Chỉ xem log LỖI (Error)
```bash
cat logs/app-2026-04-15.info.log | grep '"level":"error"' | pino-pretty
```

##### Chỉ xem log của một Module (VD: DatabaseSeeder)
```bash
cat logs/app-2026-04-15.info.log | grep "DatabaseSeeder" | pino-pretty
```

##### Theo dõi trực tiếp (Real-time) 1 Request cụ thể
```bash
tail -f logs/app-2026-04-15.info.log | grep "sys-104531" | pino-pretty
```