package edu.purdue.cuttlefish.evaluation.tpch

import java.io.{BufferedWriter, File, FileWriter}
import edu.purdue.cuttlefish.evaluation.tpch.Config.{ExecutionMode, getTable}
import edu.purdue.cuttlefish.spark.{Config => SparkConfig}
import org.apache.spark.sql._

import scala.collection.GenSeq
import scala.sys.exit

/**
  * Parent class for TPC-H queries.
  *
  * Savvas Savvides <savvas@purdue.edu>
  *
  */

abstract class Query(spark: SparkSession, executionMode: ExecutionMode.Value) {
    import Query._
    lazy val customer: DataFrame = getTable(spark, executionMode, "customer", fsChosen, pathSuffix)
    lazy val lineitem: DataFrame = getTable(spark, executionMode, "lineitem", fsChosen, pathSuffix)
    lazy val nation: DataFrame = getTable(spark, executionMode, "nation", fsChosen, pathSuffix)
    lazy val order: DataFrame = getTable(spark, executionMode, "orders", fsChosen, pathSuffix)
    lazy val region: DataFrame = getTable(spark, executionMode, "region", fsChosen, pathSuffix)
    lazy val supplier: DataFrame = getTable(spark, executionMode, "supplier", fsChosen, pathSuffix)
    lazy val part: DataFrame = getTable(spark, executionMode, "part", fsChosen, pathSuffix)
    lazy val partsupp: DataFrame = getTable(spark, executionMode, "partsupp", fsChosen, pathSuffix)

    /**
      * Get the name of the class excluding dollar signs and package
      */
    private def getClassName(): String = {
        this.getClass.getName.split("\\.").last.replaceAll("\\$", "")
    }

    /**
      * Get the results from a dataframe
      */
    def getResults(df: DataFrame) = df.collect()

    /**
      * Executes the actual query
      *
      * @return an array containing the results
      */
    def execute(): GenSeq[Row]
}

abstract class QueryMod(spark: SparkSession, executionMode: ExecutionMode.Value) {
    import Query._
    lazy val customer: DataFrame = getTable(spark, executionMode, "customer", fsChosen, pathSuffix)
    lazy val lineitem: DataFrame = getTable(spark, executionMode, "lineitem", fsChosen, pathSuffix)
    lazy val nation: DataFrame = getTable(spark, executionMode, "nation", fsChosen, pathSuffix)
    lazy val order: DataFrame = getTable(spark, executionMode, "orders", fsChosen, pathSuffix)
    lazy val region: DataFrame = getTable(spark, executionMode, "region", fsChosen, pathSuffix)
    lazy val supplier: DataFrame = getTable(spark, executionMode, "supplier", fsChosen, pathSuffix)
    lazy val part: DataFrame = getTable(spark, executionMode, "part", fsChosen, pathSuffix)
    lazy val partsupp: DataFrame = getTable(spark, executionMode, "partsupp", fsChosen, pathSuffix)
//    lazy val interimQ01 = getIntrmTable()

    /**
     * Get the name of the class excluding dollar signs and package
     */
    private def getClassName(): String = {
        this.getClass.getName.split("\\.").last.replaceAll("\\$", "")
    }

    /**
     * Get the results from a dataframe
     */
    def getResults(df: DataFrame) = df.collect()

//    def getInterimRes(): Dataset[Row]
    /**
     * Executes the actual query, and returns post-computation time
     *
     * @return an array containing the results
     */
    def execute(): (GenSeq[Row], Double)
}

abstract class PtxtQuery(spark: SparkSession) extends Query(spark, ExecutionMode.PTXT) {}

abstract class PheQuery(spark: SparkSession) extends QueryMod(spark, ExecutionMode.PHE) {}

case class CustomException(s: String)  extends Exception(s)

object Query {

    def outputResults(results: GenSeq[Row]): Unit = {
        results.foreach(row => println(row.mkString("\t")))
    }
    var fsChosen: Int = 1;
    var pathSuffix: String = "no/path/suffix";

    /**
     * returns mean and variance of a list of doubles
     * @param inSamples
     * @param totalSize
     * @return
     */
    def collectMeanStd(inSamples: List[Double], totalSize: Double): List[Double] = {
        //    val l = inSamples.map(x => x.toDouble)
        val l = inSamples
        val mean = l.sum / totalSize
        val sumsOfSquares = l.map(i => i * i).sum

        val varianceSample = if (totalSize !=1) (sumsOfSquares - (totalSize*mean*mean))/(totalSize - 1) else 0
        //    val variancePop = (sumsOfSquares/totalSize) - mean*mean
        List(mean, Math.sqrt(varianceSample))
    }

    /**
     * exectues a query once and returns the numbers
     * @param query
     * @return
     */
//    def execQueryOnce(query: QueryMod, queryPath: String): (GenSeq[Row], String, Double, Double) = {
    def execQueryOnce(query: QueryMod): (GenSeq[Row], Double, Double) = {
        val startTime = System.nanoTime()
        val (results, startClientSide) = query.execute()

        val elapsed = (System.nanoTime() - startTime) / 1000000000d
        val totalClientSide = (System.nanoTime() - startClientSide)/ 1000000000d
        // write to file instead of std out
//        outputResults(results)
//        writeTimeToFile((queryPath, elapsed, totalClientSide))
        (results, elapsed, totalClientSide)
    }

    /**
     * executes a query runs times and returns all execution numbers
     * @param query
     * @param runs
     * @return
     */
    def statsOfQuery(query: QueryMod, runs: Int): (GenSeq[Row], List[List[Double]], List[Double], List[Double]) = {
        val allResults: IndexedSeq[(GenSeq[Row], Double, Double)]  =     (0 until runs)
          .map(run => execQueryOnce(query))

//        val allResultRows: List[List[GenSeq[Row]]] = allResults.map(tup => List(tup._1)).toList
        val allResultRows: List[GenSeq[Row]] = allResults.map(tup => tup._1).toList
        // before transpose: List(List(total1, client1), List(total2, client2), List(totalN, clientN))
        val allRawNumbers: List[List[Double]] = allResults.map(tup => List(tup._2, tup._3)).toList

        // results in List(List(total1, .., totalN), List(client1, .., clientN))
        val allNumbersGrouped = allRawNumbers.transpose
        // results in List(List(mean, std), List(mean, std)).transpose
        // = List(List(meanTotal, meanClient), List(stdTotal, stdClient))
        val statsComputed = allNumbersGrouped.map(numFromAllRuns => collectMeanStd(numFromAllRuns, runs)).transpose
        // List(meanTotal, meanClient)
        val allAvg = statsComputed(0)
        // List(stdTotal, stdClient)
        val allStd = statsComputed(1)
        (allResultRows(0), allRawNumbers, allAvg, allStd)
    }

    def warmupQuery(query: QueryMod, runs: Int): Unit = {
        (0 until runs).foreach(run => query.execute())
    }

    def executeQuery(query: QueryMod, measuredRuns: Int): (GenSeq[Row], List[List[Double]], Double, Double, Double, Double) = {
        warmupQuery(query: QueryMod, 1)
        val (firstResultRows, allRaw, allAverage, allStd) = statsOfQuery(query, measuredRuns)
        // print results here
//        outputResults(firstResultRows)
//        val output = outputResults(header, results)
        val avgTuple = (allAverage(0), allAverage(1))
        val stdTuple = (allStd(0), allStd(1))
        // allRaw: List(List(total1, client1), List(total2, client2), List(totalN, clientN))
        (firstResultRows, allRaw, avgTuple._1, avgTuple._2, stdTuple._1, stdTuple._2)
    }

    /**
      * Execute 1 or more queries
      *
      * @param spark         the spark session under which the queries are to be executed
      * @param executionMode the execution mode to use, i.e., plaintext, phe, etc..
      * @param queryNum      the query to run. If 0, execute all tpc-h queries
      * @return a list of (Query name, Execution time)
      */
    def executeQueries(spark: SparkSession, executionMode: ExecutionMode.Value, queryNum: Int, measuredRuns: Int): Unit = {

        if (queryNum < 0 || queryNum > 22)
            throw new IllegalArgumentException("Query Number must be in range [0, 22]")

        val packageName = this.getClass.getPackage().getName
        val modeString = Config.executionModeMap(executionMode)

        // decide what queries to execute
        val queryFrom = if (queryNum == 0) 1 else queryNum
        val queryTo = if (queryNum <= 0) 22 else queryNum

        // record execution times
//        var times = List[(String, Double, Double)]()

        for (queryNo <- queryFrom to queryTo) {
            val queryName = f"Q${queryNo}%02d"
            val queryPath = packageName + "." + modeString + "." + queryName
            val query = Class.forName(queryPath).getConstructor(classOf[SparkSession]).newInstance(spark).asInstanceOf[QueryMod]


            println("Executing Query: " + queryPath)
            println("===============================================================")
//            val startTime = System.nanoTime()
//            val (results, startClientSide) = query.execute()
//
//            val elapsed = (System.nanoTime() - startTime) / 1000000000d
//            val totalClientSide = (System.nanoTime() - startClientSide)/ 1000000000d
//            outputResults(results)
//
//            writeTimeToFile((queryPath, elapsed, totalClientSide))
//            times = times :+ (queryPath, elapsed, totalClientSide)
            val (firstResultRows, allRawTimes, avgTotalTime, avgClientSide, stdTotalTime, stdClientSide) = executeQuery(query: QueryMod, measuredRuns: Int)

            outputResults(firstResultRows)
            writeAllTimes(firstResultRows, allRawTimes, queryPath, avgTotalTime, avgClientSide, stdTotalTime, stdClientSide)
//            writeTimeToFile((queryPath, elapsed, totalClientSide))
//            times = times :+ (queryPath, elapsed, totalClientSide)
            println()
        }
//        times
    }

    def delIfExists(someFile: File): Unit = {
        if (someFile.exists()) {
            someFile.delete()
        }
    }
//    def writeAllTimes(times: List[(String, Double, Double)]): Unit = {
    def writeAllTimes(firstResult: GenSeq[Row], rawTimes: List[List[Double]], queryPath: String, avgTotalTime: Double, avgClientSide: Double, stdTotalTime: Double, stdClientSide: Double): Unit = {

        val timesFile  = new File("TIMES_raw.txt")
        delIfExists(timesFile)
        val timesStdFile  = new File("TIMES_std.txt")
        delIfExists(timesStdFile)
        val timesAvgFile  = new File("TIMES_avg.txt")
        delIfExists(timesAvgFile)
        val outputFile = new File("OUTPUT.txt")
        delIfExists(outputFile)

        val bwTimesFile = new BufferedWriter(new FileWriter(timesFile, true))
        rawTimes.foreach(iRun => bwTimesFile.write(f"${queryPath}%s\t${iRun(0)}%1.8f\t${iRun(1)}%1.8f\n"))
        bwTimesFile.close()

        val bwTimesAvgFile = new BufferedWriter(new FileWriter(timesAvgFile, true))
        bwTimesAvgFile.write(f"${queryPath}%s\t${avgTotalTime}%1.8f\t${avgClientSide}%1.8f\n")
        bwTimesAvgFile.close()

        val bwTimesStdFile = new BufferedWriter(new FileWriter(timesStdFile, true))
        bwTimesStdFile.write(f"${queryPath}%s\t${stdTotalTime}%1.8f\t${stdClientSide}%1.8f\n")
        bwTimesStdFile.close()

        val bwOutputFile = new BufferedWriter(new FileWriter(outputFile, true))
        firstResult.foreach(row => bwOutputFile.write(row.mkString("\t")))
//        bwOutputFile.write(f"${queryPath}%s\t${stdTotalTime}%1.8f\t${stdClientSide}%1.8f\n")
        bwOutputFile.close()
    }

//    def writeRawTimes(times: List[(String, Double, Double)]): Unit = {
//        val outFile = new File("TIMES_raw.txt")
//        val bw = new BufferedWriter(new FileWriter(outFile, true))
//        times.foreach {
//            case (key, elapsed, clientSide) => bw.write(f"${key}%s\t${elapsed}%1.8f\t${clientSide}%1.8f\n")
////            case (key, value) => bw.write(f"${value}%1.8f\n")
//        }
//        bw.close()
//    }

    def writeTimeToFile(time: (String, Double, Double)): Unit = {
        val outFile = new File("TIMES.txt")
        val bw = new BufferedWriter(new FileWriter(outFile, true))
        time match {
            case (key, elapsed, clientSide) => bw.write(f"${key}%s\t${elapsed}%1.8f\t${clientSide}%1.8f\n")
//            case (key, value) => bw.write(f"${value}%1.8f\n")
        }
        bw.close()
    }

    def main(args: Array[String]): Unit = {
        if (args.length == 0) {
            println(" Usage eg.: ${SPARK_HOME}/bin/spark-submit" +
              " --class edu.purdue.cuttlefish.evaluation.tpch.Query" +
              " ${CUTTLEFISH_HOME}/target/cuttlefish-0.0.1-SNAPSHOT.jar" +
              " phe 0 resources/data_input/tblSilo/10MBtBL")
            throw  new CustomException(" Usage eg.: ${SPARK_HOME}/bin/spark-submit " +
              "--master yarn --deploy-mode client" +
              " --class edu.purdue.cuttlefish.evaluation.tpch.Query" +
              " ${CUTTLEFISH_HOME}/target/cuttlefish-0.0.1-SNAPSHOT.jar" +
              " phe 0 resources/data_input/tblSilo/10MBtBL")
        }
        val executionMode = if (args.length > 0) {
            val mode = args(0)
            if (mode == "ptxt")
                ExecutionMode.PTXT
            else if (mode == "phe")
                ExecutionMode.PHE
            else
                ExecutionMode.PTXT
        } else
            ExecutionMode.PTXT

        // let's say 1 is HDFS, 0 is Local
        fsChosen = if (args.length > 1) args(1).toInt else 0

        // for local path is: SparkConfig.CUTTLEFISH_HOME + "/resources/data_input/100MB"
        pathSuffix = if (args.length > 2) args(2) else "/pathSuffix/not/entered. For Hdfs enter path relative to master"

        val measuredRuns: Int = if (args.length > 3) args(3).toInt else 3

        val queryNum = if (args.length > 4) args(4).toInt else 0

        val appName = if (queryNum == 0) "TPC-H" else "TPC-H Q" + queryNum
        val spark = SparkConfig.getDefaultSpark(appName)

        val times = executeQueries(spark, executionMode, queryNum, measuredRuns)
//        writeTimes(times)
    }
}
