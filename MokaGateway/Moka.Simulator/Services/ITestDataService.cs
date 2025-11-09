namespace Moka.Simulator.Services;

using Moka.Simulator.Models;

public interface ITestDataService
{
 List<TestCard> GetTestCards();
 string GetErrorMessage(string? code);
}
