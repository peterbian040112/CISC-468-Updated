

## Folder Structure

The workspace contains two folders by default, where:

- `src`: the folder to maintain sources
- `lib`: the folder to maintain dependencies

Meanwhile, the compiled output files will be generated in the `bin` folder by default.


## Usage

Since the project is managed by VS Code, we'll use VS Code to help us compile. Click the run and in the command line, type the following:

run

`java -cp "bin;lib/jmdns-3.6.0.jar;lib/slf4j-api-1.7.36.jar;lib/slf4j-simple-1.7.36.jar;lib/bcprov-jdk18on-1.80.jar" secureshare.SecureShareClient [clientName] --port [portNumber]`


Or if the IDE does not support compiling, typing
compile

`javac -cp "lib/*" -d bin src/secureshare/*.java`



For the instruction 

`help `

will list all the commands
