package edu.purdue.cuttlefish.evaluation.tpch

import edu.purdue.cuttlefish.evaluation.tpch.Config._
import edu.purdue.cuttlefish.spark.{UDF, Config => SparkConfig}
import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.functions.col

object EncryptTables {

    def encColumn(columnName: String) = {
//        println("[encColumn] Getting column: " + columnName + "\n Printing Map\n")
//        Schema.encryptOptionsMap foreach (x => println (x._1 + "-->" + x._2))
        val encOptions = Schema.encryptOptionsMap
          .get(columnName).get
        UDF.encrypt(encOptions.scheme, encOptions.f)
    }

    def encTable(spark: SparkSession, tableName: String, fsChosen: Int, pathSuffix: String) = {

        println("Encrypting " + tableName)

        val tableDF = getTable(spark, ExecutionMode.PTXT, tableName, fsChosen, pathSuffix)
        val tableColumns = tableDF.columns

        tableDF
          .select(tableColumns.map(c => encColumn(c)(col(c)).alias(c)): _*)
          .write
          .mode("overwrite")
          .parquet(getPath(ExecutionMode.PHE, tableName, fsChosen, pathSuffix))
    }

    def main(args: Array[String]): Unit = {
        val spark = SparkConfig.getDefaultSpark("Encrypt TPC-H Tables", "local")
        if (args.length == 0) {
            println(" Usage eg.: ${SPARK_HOME}/bin/spark-submit" +
              "--master yarn --deploy-mode client" +
              " --class edu.purdue.cuttlefish.evaluation.tpch.Query" +
              " ${CUTTLEFISH_HOME}/target/cuttlefish-0.0.1-SNAPSHOT.jar" +
              " 0 resources/data_input/tblSilo/10MBtBL")
            throw new ArrayIndexOutOfBoundsException;
        }

        // let's say 1 is HDFS, 0 is Local
        val fsChosen = if (args.length > 0) args(0).toInt else 0

        // for local path is: SparkConfig.CUTTLEFISH_HOME + "resources/data_input/100MB"
        val pathSuffix = if (args.length > 1) args(1) else "pathSuffix/not/entered"
        TABLE_NAMES.foreach(tableName => encTable(spark, tableName, fsChosen, pathSuffix))
    }
}
