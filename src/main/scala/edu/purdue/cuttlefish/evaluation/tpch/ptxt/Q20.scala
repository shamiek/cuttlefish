package edu.purdue.cuttlefish.evaluation.tpch.ptxt

import edu.purdue.cuttlefish.evaluation.tpch.PtxtQuery
import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.functions.{sum, udf}

class Q20(spark: SparkSession) extends PtxtQuery(spark) {

    override def execute() = {
        import spark.implicits._

        val forest = udf { (x: String) => x.startsWith("forest") }

        val flineitem = lineitem
          .filter($"l_shipdate" >= "1994-01-01" && $"l_shipdate" < "1995-01-01")
          .groupBy($"l_partkey", $"l_suppkey")
          .agg((sum($"l_quantity") * 0.5).as("sum_quantity"))

        val fnation = nation
          .filter($"n_name" === "CANADA")
        val nat_supp = supplier
          .select($"s_suppkey", $"s_name", $"s_nationkey", $"s_address")
          .join(fnation, $"s_nationkey" === fnation("n_nationkey"))

        val q = part
          .filter(forest($"p_name"))
          .select($"p_partkey").distinct
          .join(partsupp, $"p_partkey" === partsupp("ps_partkey"))
          .join(flineitem, $"ps_suppkey" === flineitem("l_suppkey") && $"ps_partkey" === flineitem("l_partkey"))
          .filter($"ps_availqty" > $"sum_quantity")
          .select($"ps_suppkey").distinct
          .join(nat_supp, $"ps_suppkey" === nat_supp("s_suppkey"))
          .select($"s_name", $"s_address")
          .sort($"s_name")

        getResults(q)
    }
}
