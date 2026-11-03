"""Independent Autoruns VQL oracles for synthetic parity tests."""
from vraptor.hunt import live


def autoruns_accounting_vql(where: str, *, source=None) -> str:
    """Accounting baseline; calls live.source_vql through the module so tests can patch it."""
    return (
        live.source_query_preamble(source)
        + live.autoruns_golden_query_preamble(where)
        + "LET AutorunsAccountingRows = SELECT *, "
        + f"if(condition={where or 'TRUE'}, then=1, else=0) AS Residual\n"
        + f"FROM {live.source_vql(source)}\n"
        + "SELECT count() AS SourceRows, sum(item=Residual) AS ResidualRows, "
        + "sum(item=if(condition=Residual AND (`Image Path` OR `Launch String`), "
        + "then=1, else=0)) AS PopulatedRows\n"
        + "FROM AutorunsAccountingRows GROUP BY TRUE"
    )
